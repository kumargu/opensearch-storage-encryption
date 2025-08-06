/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.read_ahead;

import java.io.Closeable;
import java.nio.file.Path;

/**
 * High-level facade for managing readahead operations for DirectIO IndexInputs.
 * <p>
 * Coordinates:
 * <ul>
 *     <li>Per-stream {@link ReadAheadContext}</li>
 *     <li>Adaptive windowing policy</li>
 *     <li>Async scheduling to a {@link Worker}</li>
 * </ul>
 *
 * Typical flow:
 * <pre>
 *   ReadAheadContext ctx = manager.register(path, offset);
 *
 *   // on each segment load in IndexInput:
 *   manager.onSegmentAccess(ctx, segmentIndex, cacheMiss);
 *
 *   // on close:
 *   manager.cancel(ctx);
 * </pre>
 */
public interface ReadAheadManager extends Closeable {

    ReadAheadContext register(Path path, long fileLength);

    /**
     * Notify that a segment was accessed, possibly triggering readahead.
     *
     * @param context       per-index input context
     * @param startFileOffset  the fileoffset from where we start reading.
     * @param cacheMiss     true if the block was not in cache (enables RA)
     */
    void onSegmentAccess(ReadAheadContext context, long startFileOffset, boolean cacheMiss);

    /**
     * Cancel all readahead for a given stream context.
     *
     * @param context the readahead context to cancel
     */
    void cancel(ReadAheadContext context);

    /**
     * Cancel all pending requests for a given file.
     *
     * @param path file path to cancel
     */
    void cancel(Path path);

    /**
     * Shutdown the entire readahead system, canceling all contexts and workers.
     */
    @Override
    void close();
}
