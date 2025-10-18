/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.read_ahead.impl;

import static org.opensearch.index.store.directio.DirectIoConfigs.CACHE_BLOCK_SIZE_POWER;

import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.LockSupport;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.index.store.read_ahead.ReadaheadContext;
import org.opensearch.index.store.read_ahead.ReadaheadPolicy;
import org.opensearch.index.store.read_ahead.Worker;

/**
 * Windowed readahead context implementation that manages adaptive prefetching
 * for sequential file access patterns.
 * 
 * <p>This implementation uses a configurable window-based readahead strategy
 * that adapts to access patterns. It coordinates with a Worker to schedule
 * bulk prefetch operations and integrates with cache miss/hit feedback to
 * optimize readahead behavior.
 *
 * @opensearch.internal
 */
public class WindowedReadAheadContext implements ReadaheadContext {
    private static final Logger LOGGER = LogManager.getLogger(WindowedReadAheadContext.class);

    private final Path path;
    private final long fileLength;
    private final Worker worker;
    private final WindowedReadaheadPolicy policy;
    private final Thread processingThread; // Reference for unpark

    // High bit indicates cache hit (1) or miss (0), lower 63 bits store block offset
    private static final long HIT_FLAG = 1L << 63;
    private static final long OFFSET_MASK = ~HIT_FLAG;
    private static final long NO_ACCESS = -1L;

    private final AtomicLong pendingAccess = new AtomicLong(NO_ACCESS);

    // Watermark: last scheduled end block (exclusive) to avoid redundant triggers
    private volatile long lastScheduledEndBlock = 0;

    // Scheduling state (per file)
    private final AtomicBoolean closed = new AtomicBoolean(false);

    private WindowedReadAheadContext(Path path, long fileLength, Worker worker, WindowedReadaheadPolicy policy, Thread processingThread) {
        this.path = path;
        this.fileLength = fileLength;
        this.worker = worker;
        this.policy = policy;
        this.processingThread = processingThread;
    }

    /**
     * Creates a new WindowedReadAheadContext with the specified configuration.
     *
     * @param path the file path for readahead operations
     * @param fileLength the total length of the file in bytes
     * @param worker the worker to schedule readahead operations
     * @param config the readahead configuration settings
     * @param processingThread the background thread for unpark notifications
     * @return a new WindowedReadAheadContext instance
     */
    public static WindowedReadAheadContext build(
        Path path,
        long fileLength,
        Worker worker,
        WindowedReadAheadConfig config,
        Thread processingThread
    ) {
        var policy = new WindowedReadaheadPolicy(
            path,
            config.initialWindow(),
            config.maxWindowSegments(),
            config.shrinkOnRandomThreshold()
        );
        return new WindowedReadAheadContext(path, fileLength, worker, policy, processingThread);
    }

    @Override
    public void onAccess(long blockOffset, boolean wasHit) {
        if (closed.get())
            return;

        // Encode access into single long: high bit = hit/miss, lower 63 bits = offset
        // This is a simple atomic store - extremely fast (~2ns)
        long encoded = (blockOffset & OFFSET_MASK) | (wasHit ? HIT_FLAG : 0);
        pendingAccess.set(encoded);

        // Unpark processing thread for low-latency response
        if (processingThread != null) {
            LockSupport.unpark(processingThread);
        }
    }

    /**
     * Processes pending access notification. Called by background thread in ReadaheadManager.
     * Returns true if there was a pending access to process.
     */
    public boolean processPendingAccess() {
        if (closed.get())
            return false;

        // Get and clear pending access atomically
        long encoded = pendingAccess.getAndSet(NO_ACCESS);
        if (encoded == NO_ACCESS) {
            return false; // No pending access
        }

        // Decode hit/miss and offset
        boolean wasHit = (encoded & HIT_FLAG) != 0;
        long blockOffset = encoded & OFFSET_MASK;
        long currentBlock = blockOffset >>> CACHE_BLOCK_SIZE_POWER;

        if (wasHit) {
            policy.onCacheHit();

            // Hit-ahead: if we're near the tail of scheduled window, extend it
            // Check if current block is in the "guard band" near lastScheduledEndBlock
            long scheduledEnd = lastScheduledEndBlock;
            if (scheduledEnd > 0) {
                long leadBlocks = policy.leadBlocks();
                long guardStart = scheduledEnd - leadBlocks;

                // If hit crosses into guard band, pre-trigger extension
                if (currentBlock >= guardStart && currentBlock < scheduledEnd) {
                    if (LOGGER.isDebugEnabled()) {
                        LOGGER.debug("Hit-ahead trigger: block={} guard=[{}-{})", currentBlock, guardStart, scheduledEnd);
                    }
                    trigger(blockOffset);
                }
            }
        } else {
            // Cache miss - check if we should trigger readahead
            if (policy.shouldTrigger(blockOffset)) {
                trigger(blockOffset);
            }
        }

        return true;
    }

    @Override
    public void onCacheMiss(long fileOffset) {
        onAccess(fileOffset, false);
    }

    @Override
    public void onCacheHit() {
        onAccess(-1L, true); // Offset doesn't matter for hits
    }

    private void trigger(long anchorFileOffset) {
        if (closed.get() || worker == null)
            return;

        final long startSeg = anchorFileOffset >>> CACHE_BLOCK_SIZE_POWER;
        final long lastSeg = (fileLength - 1) >>> CACHE_BLOCK_SIZE_POWER;
        final long safeEndSeg = Math.max(0, lastSeg - 3); // Skip last 4 segments (footer)

        final long windowSegs = policy.currentWindow();
        if (windowSegs <= 0 || startSeg > safeEndSeg)
            return;

        final long endExclusive = Math.min(startSeg + windowSegs, safeEndSeg + 1);
        if (startSeg >= endExclusive)
            return;

        // Watermark check: if desired end is already covered, skip scheduling
        long currentWatermark = lastScheduledEndBlock;
        if (endExclusive <= currentWatermark) {
            if (LOGGER.isTraceEnabled()) {
                LOGGER.trace("Skipping trigger: endExclusive={} <= watermark={}", endExclusive, currentWatermark);
            }
            return;
        }

        final long blockCount = endExclusive - startSeg;

        if (blockCount > 0) {
            // Schedule the entire window
            final boolean accepted = worker.schedule(path, anchorFileOffset, blockCount);

            if (accepted) {
                // Update watermark: we've scheduled up to endExclusive
                lastScheduledEndBlock = endExclusive;
            }

            LOGGER
                .debug(
                    "RA_BULK_TRIGGER path={} anchorOff={} startSeg={} endExclusive={} windowSegs={} scheduledBlocks={} accepted={} watermark={}",
                    path,
                    anchorFileOffset,
                    startSeg,
                    endExclusive,
                    windowSegs,
                    blockCount,
                    accepted,
                    lastScheduledEndBlock
                );

            if (!accepted) {
                LOGGER
                    .info(
                        "Window bulk readahead backpressure path={} length={} startSeg={} endExclusive={} windowBlocks={}",
                        path,
                        fileLength,
                        startSeg,
                        endExclusive,
                        blockCount
                    );
            }
        }
    }

    @Override
    public ReadaheadPolicy policy() {
        return this.policy;
    }

    @Override
    public void triggerReadahead(long fileOffset) {
        trigger(fileOffset);
    }

    @Override
    public void reset() {
        policy.reset();
    }

    @Override
    public void cancel() {
        if (worker != null) {
            worker.cancel(path);
        }
    }

    @Override
    public boolean isReadAheadEnabled() {
        return !closed.get();
    }

    @Override
    public void close() {
        if (closed.compareAndSet(false, true)) {
            cancel();
        }
    }
}
