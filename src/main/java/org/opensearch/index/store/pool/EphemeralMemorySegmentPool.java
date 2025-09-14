/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.pool;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.util.concurrent.TimeUnit;

import org.opensearch.common.SuppressForbidden;

@SuppressWarnings("preview")
@SuppressForbidden(reason = "allocates standalone arenas per segment")
public class EphemeralMemorySegmentPool implements Pool<MemorySegment>, AutoCloseable {
    private final Arena arena;
    private final int segmentSize;

    public EphemeralMemorySegmentPool(int segmentSize) {
        this.segmentSize = segmentSize;
        this.arena = Arena.ofShared();
    }

    @Override
    public MemorySegment acquire() {
        return arena.allocate(segmentSize);
    }

    @Override
    public void release(MemorySegment segment) {
        close();
    }

    @Override
    public void close() {
        arena.close();

    }

    @Override
    public MemorySegment tryAcquire(long timeout, TimeUnit unit) throws InterruptedException {
        return acquire();
    }

    @Override
    public long totalMemory() {
        throw new UnsupportedOperationException("Unimplemented method 'totalMemory'");
    }

    @Override
    public String poolStats() {
        return String.format("EphemeralPool[size=%d]", segmentSize);
    }

    @Override
    public long availableMemory() {
        throw new UnsupportedOperationException("Unimplemented method 'availableMemory'");
    }

    @Override
    public int pooledSegmentSize() {
        throw new UnsupportedOperationException("Unimplemented method 'pooledSegmentSize'");
    }

    @Override
    public boolean isUnderPressure() {
        throw new UnsupportedOperationException("Unimplemented method 'isUnderPressure'");
    }

    @Override
    public void warmUp(long numBlocks) {
        throw new UnsupportedOperationException("Unimplemented method 'warmUp'");
    }

    @Override
    public boolean isClosed() {
        throw new UnsupportedOperationException("Unimplemented method isClosed");
    }
}
