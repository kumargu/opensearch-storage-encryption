/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.pool;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.SuppressForbidden;

@SuppressWarnings("preview")
@SuppressForbidden(reason = "uses custom DirectIO")
public class PrimaryMemorySegmentPool implements Pool<MemorySegment>, AutoCloseable {
    private static final Logger LOGGER = LogManager.getLogger(MemorySegmentPool.class);

    private final ReentrantLock lock = new ReentrantLock();
    private final Condition notEmpty = lock.newCondition();
    private final Deque<MemorySegment> freeList = new ArrayDeque<>();
    private final Arena sharedArena;
    private final int segmentSize;
    private final int maxSegments;
    private final long totalMemory;
    private final boolean requiresZeroing;

    private volatile boolean closed = false;
    private int allocatedSegments = 0;

    // Cached values to reduce lock overhead
    private volatile int cachedFreeListSize = 0;

    /**
     * Creates a pool with lazy allocation and optional zeroing
     */
    public PrimaryMemorySegmentPool(long totalMemory, int segmentSize) {
        this(totalMemory, segmentSize, true);
    }

    /**
     * Creates a pool with configurable allocation strategy and zeroing
     * 
     * @param totalMemory total memory to manage
     * @param segmentSize size of each segment
     * @param requiresZeroing if true, zero segments on release; if false, skip for performance
     */
    public PrimaryMemorySegmentPool(long totalMemory, int segmentSize, boolean requiresZeroing) {
        if (totalMemory % segmentSize != 0) {
            throw new IllegalArgumentException("Total memory must be a multiple of segment size");
        }
        this.totalMemory = totalMemory;
        this.segmentSize = segmentSize;
        this.maxSegments = (int) (totalMemory / segmentSize);
        this.sharedArena = Arena.ofShared();
        this.requiresZeroing = requiresZeroing;
    }

    @Override
    public MemorySegment acquire() throws InterruptedException {
        lock.lock();
        try {
            // Try to get from free list first
            if (!freeList.isEmpty()) {
                MemorySegment segment = freeList.removeFirst();
                cachedFreeListSize = freeList.size();
                return segment;
            }

            // Try to allocate new segment if under capacity
            if (allocatedSegments < maxSegments) {
                MemorySegment segment = sharedArena.allocate(segmentSize);
                allocatedSegments++;
                LOGGER.trace("Allocated new segment, total allocated: {}", allocatedSegments);
                return segment;
            }

            if (closed) {
                throw new IllegalStateException("Pool is closed");
            }

            throw new PrimaryPoolExhaustedException();
        } finally {
            lock.unlock();
        }
    }

    @Override
    public MemorySegment tryAcquire(long timeout, TimeUnit unit) throws InterruptedException {
        lock.lock();
        try {
            if (!freeList.isEmpty()) {
                MemorySegment segment = freeList.removeFirst();
                cachedFreeListSize = freeList.size();
                LOGGER.trace("Acquired segment from free list: remaining free={}", cachedFreeListSize);
                return segment;
            }

            // Try to allocate new segment if under capacity
            if (allocatedSegments < maxSegments) {
                MemorySegment segment = sharedArena.allocate(segmentSize);
                allocatedSegments++;
                return segment;
            }

            if (closed) {
                LOGGER.error("Pool is closed - cannot acquire segment");
                throw new IllegalStateException("Pool is closed");
            }

            LOGGER
                .debug(
                    "Pool exhausted: no free segments available. Pool stats: allocated={}/{}, free={}",
                    allocatedSegments,
                    maxSegments,
                    freeList.size()
                );
            throw new PrimaryPoolExhaustedException();
        } finally {
            lock.unlock();
        }
    }

    @Override
    public void release(MemorySegment segment) {
        lock.lock();
        try {
            if (closed) {
                return; // Don't add back to closed pool
            }

            // Optional zeroing for security vs performance trade-off
            if (requiresZeroing) {
                segment.fill((byte) 0);
            }

            freeList.addLast(segment);
            cachedFreeListSize = freeList.size();
            notEmpty.signal();
        } finally {
            lock.unlock();
        }
    }

    /**
     * Bulk release for releasing multiple segments
     */
    public void releaseAll(MemorySegment... segments) {
        if (segments.length == 0)
            return;

        lock.lock();
        try {
            if (closed)
                return;

            for (MemorySegment segment : segments) {
                if (requiresZeroing) {
                    segment.fill((byte) 0);
                }
                freeList.addLast(segment);
            }
            cachedFreeListSize = freeList.size();
            notEmpty.signalAll(); // Wake up multiple waiters
        } finally {
            lock.unlock();
        }
    }

    @Override
    public long totalMemory() {
        return totalMemory;
    }

    @Override
    public long availableMemory() {
        // Fast path using cached value to avoid locking
        int free = cachedFreeListSize;
        int allocated = allocatedSegments; // volatile read
        int canAllocate = Math.max(0, maxSegments - allocated);
        return (long) (free + canAllocate) * segmentSize;
    }

    /**
     * More accurate but slower version requiring lock
     */
    public long availableMemoryAccurate() {
        lock.lock();
        try {
            int free = freeList.size();
            int canAllocate = Math.max(0, maxSegments - allocatedSegments);
            return (long) (free + canAllocate) * segmentSize;
        } finally {
            lock.unlock();
        }
    }

    @Override
    public int pooledSegmentSize() {
        return segmentSize;
    }

    /**
     * Get current pool utilization statistics
     */
    public PoolStats getStats() {
        return new PoolStats(maxSegments, allocatedSegments, freeList.size(), maxSegments - allocatedSegments);
    }

    /**
     * Check if pool is under memory pressure
     */
    @Override
    public boolean isUnderPressure() {
        return allocatedSegments > (maxSegments * 0.9) && cachedFreeListSize < (maxSegments * 0.1);
    }

    /**
     * Warm up the pool by pre-allocating segments up to target count
     */
    @Override
    public void warmUp(long targetSegments) {
        targetSegments = Math.min(targetSegments, maxSegments);

        if (allocatedSegments >= targetSegments)
            return;

        lock.lock();
        try {
            while (allocatedSegments < targetSegments) {
                freeList.add(sharedArena.allocate(segmentSize));
                allocatedSegments++;
            }
            cachedFreeListSize = freeList.size();
        } finally {
            lock.unlock();
        }
    }

    @Override
    public void close() {
        lock.lock();
        try {
            if (closed)
                return;
            closed = true;
            cachedFreeListSize = 0;
            notEmpty.signalAll();
        } finally {
            lock.unlock();
        }

        if (sharedArena.scope().isAlive()) {
            sharedArena.close();
        }
    }

    @Override
    public String poolStats() {
        int free = cachedFreeListSize;
        int allocated = allocatedSegments;
        int unallocated = maxSegments - allocated;
        return new PoolStats(maxSegments, allocated, free, unallocated).toString();
    }

    /**
     * Pool statistics for monitoring
     */
    @SuppressForbidden(reason = "uses custom string builder")
    public static class PoolStats {
        public final int maxSegments;
        public final int allocatedSegments;
        public final int freeSegments;
        public final int unallocatedSegments;
        public final double utilizationRatio;
        public final double pressureRatio;

        PoolStats(int maxSegments, int allocatedSegments, int freeSegments, int unallocatedSegments) {
            this.maxSegments = maxSegments;
            this.allocatedSegments = allocatedSegments;
            this.freeSegments = freeSegments;
            this.unallocatedSegments = unallocatedSegments;
            this.utilizationRatio = (double) (allocatedSegments - freeSegments) / maxSegments;
            this.pressureRatio = (double) allocatedSegments / maxSegments;
        }

        @Override
        public String toString() {
            return String
                .format(
                    "PoolStats[max=%d, allocated=%d, free=%d, unallocated=%d, utilization=%.1f%%, pressure=%.1f%%]",
                    maxSegments,
                    allocatedSegments,
                    freeSegments,
                    unallocatedSegments,
                    utilizationRatio * 100,
                    pressureRatio * 100
                );
        }
    }

    @Override
    public boolean isClosed() {
        return closed;
    }
}
