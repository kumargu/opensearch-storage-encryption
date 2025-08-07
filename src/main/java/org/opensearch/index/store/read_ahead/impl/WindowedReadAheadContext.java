/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.read_ahead.impl;

import static org.opensearch.index.store.directio.DirectIoConfigs.CACHE_BLOCK_SIZE;
import static org.opensearch.index.store.directio.DirectIoConfigs.CACHE_BLOCK_SIZE_POWER;

import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.index.store.read_ahead.ReadAheadContext;
import org.opensearch.index.store.read_ahead.Worker;

public class WindowedReadAheadContext implements ReadAheadContext {
    private static final Logger LOGGER = LogManager.getLogger(WindowedReadAheadConfig.class);

    private final Path path;

    private final long fileLength;
    private final Worker worker;
    private final WindowedReadaheadPolicy policy;

    // ----- Cache-awareness state -----
    private final int hitStreakThreshold;
    private int cacheHitStreak = 0;
    private boolean readaheadEnabled = true;

    // ----- Scheduling state -----
    private volatile long lastScheduledSegment = -1;
    private final AtomicBoolean closed = new AtomicBoolean(false);

    public WindowedReadAheadContext(Path path, long fileLength, Worker worker, int hitStreakThreshold, WindowedReadaheadPolicy policy) {
        this.path = path;
        this.fileLength = fileLength;
        this.worker = worker;
        this.hitStreakThreshold = hitStreakThreshold;
        this.policy = policy;
    }

    public static WindowedReadAheadContext build(Path path, long fileLength, Worker worker, WindowedReadAheadConfig config) {
        WindowedReadaheadPolicy policy = new WindowedReadaheadPolicy(
            config.initialWindow(),
            config.maxWindowSegments(),
            config.shrinkOnRandomThreshold()
        );

        return new WindowedReadAheadContext(path, fileLength, worker, config.hitStreakThreshold(), policy);
    }

    @Override
    public synchronized void onSegmentAccess(long fileOffset, boolean cacheMiss) {
        if (closed.get()) {
            return;
        }

        // 1. Cache-awareness
        if (cacheMiss) {
            readaheadEnabled = true;
            cacheHitStreak = 0;
        } else {
            cacheHitStreak++;
            if (cacheHitStreak >= hitStreakThreshold) {
                readaheadEnabled = false;
            }
        }

        // Policy-driven sequential/random detection
        boolean trigger = policy.shouldTrigger(fileOffset);

        if (readaheadEnabled && trigger) {
            int window = policy.currentWindow();
            long startSegmentIndex = (fileOffset >>> CACHE_BLOCK_SIZE_POWER) + 1;

            triggerReadahead(startSegmentIndex, window);
        }
    }

    private void triggerReadahead(long startSegmentIndex, int windowSegments) {
        if (closed.get() || worker == null) {
            return;
        }

        // Prevent overflow when adding windowSegments
        long maxSegmentIndex = (fileLength >>> CACHE_BLOCK_SIZE_POWER);
        long endSegmentIndex = Math.min(startSegmentIndex + windowSegments, maxSegmentIndex + 1);

        for (long seg = startSegmentIndex; seg < endSegmentIndex; seg++) {
            // Skip segments already scheduled (sequential optimization)
            if (seg <= lastScheduledSegment) {
                continue;
            }

            lastScheduledSegment = seg;

            long offset = seg << CACHE_BLOCK_SIZE_POWER;
            if (offset >= fileLength) {
                break;
            }

            long remaining = fileLength - offset;
            int length = (int) Math.min(CACHE_BLOCK_SIZE, remaining);

            LOGGER.info("Triggering readahead: startSegment={} window={}", startSegmentIndex, policy.currentWindow());
            worker.schedule(path, offset, length);
        }
    }

    @Override
    public synchronized void triggerReadahead(long startSegmentIndex) {
        triggerReadahead(startSegmentIndex, policy.currentWindow());
    }

    @Override
    public synchronized void reset() {
        policy.reset();
        cacheHitStreak = 0;
        readaheadEnabled = true;
        lastScheduledSegment = -1L;
    }

    @Override
    public void cancel() {
        if (worker != null) {
            worker.cancel(path);
        }
    }

    @Override
    public boolean isReadAheadEnabled() {
        return readaheadEnabled;
    }

    @Override
    public void close() {
        if (closed.compareAndSet(false, true)) {
            cancel();
        }
    }
}
