/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.block;

import java.lang.foreign.MemorySegment;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.index.store.block_cache.BlockCacheValue;

/**
 * A reference-counted wrapper around a {@link MemorySegment} that implements {@link BlockCacheValue}.
 *
 * <h2>Purpose</h2>
 * Enables safe sharing of native memory segments across multiple concurrent readers while ensuring
 * the underlying resource is released exactly once when no longer in use.
 *
 * <h2>Reference Counting Lifecycle</h2>
 * <ol>
 *   <li><b>Creation:</b> refCount starts at 1 (represents cache's ownership)</li>
 *   <li><b>Pin:</b> Reader calls {@link #tryPin()} → refCount incremented atomically via CAS</li>
 *   <li><b>Use:</b> Reader accesses {@link #segment()} while pinned</li>
 *   <li><b>Unpin:</b> Reader calls {@link #unpin()} → refCount decremented</li>
 *   <li><b>Eviction:</b> Cache calls {@link #close()} → generation incremented, refCount decremented</li>
 *   <li><b>Release:</b> When refCount reaches 0, {@link BlockReleaser} callback returns segment to pool</li>
 * </ol>
 *
 * <h2>Generation-Based Staleness Detection</h2>
 * Uses a monotonically increasing generation counter to detect stale cached references
 * When {@link #close()} is called (segment evicted from cache), generation
 * is atomically incremented. This invalidates any locally cache entries holding
 * the old generation, preventing use of stale or recycled memory even under high cache churn.
 *
 */
public final class RefCountedMemorySegment implements BlockCacheValue<RefCountedMemorySegment> {
    private static final Logger LOGGER = LogManager.getLogger(RefCountedMemorySegment.class);

    /**
     * Pre-sliced view of the segment from [0, length).
     * Cached at construction to avoid repeated slicing on each segment() call.
     * If length equals segment size, this is just a reference to the original segment.
     */
    private final MemorySegment slicedSegment;

    /** Logical length of valid data in the segment (may be less than segment capacity). */
    private final int length;

    /**
     * VarHandle for atomic operations on the refCount field.
     * Used for CAS, increment, and decrement operations.
     */
    private static final VarHandle REFCOUNT;
    static {
        try {
            REFCOUNT = MethodHandles.lookup().findVarHandle(RefCountedMemorySegment.class, "refCount", int.class);
        } catch (IllegalAccessException | NoSuchFieldException e) {
            throw new Error(e);
        }
    }

    /**
     * Reference counter tracking active users of this segment.
     * - Starts at 1 (cache's initial reference)
     * - Incremented by {@link #incRef()} and {@link #tryPin()} when readers acquire the segment
     * - Decremented by {@link #decRef()} when released
     * - When reaches 0, segment is returned to pool via {@link #onFullyReleased}
     *
     * Uses volatile int with VarHandle (see {@link #REFCOUNT}) for atomic operations.
     * This saves 16 bytes per segment compared to AtomicInteger while maintaining equivalent
     * performance through direct VarHandle CAS operations.
     */
    private volatile int refCount = 1;

    /**
     * Callback invoked when reference count reaches zero.
     * Typically returns the segment to a memory pool for reuse.
     */
    private final BlockReleaser<RefCountedMemorySegment> onFullyReleased;

    /**
     * Generation counter incremented on each eviction (close) cycle.
     * Used to detect stale cached references.
     *
     * Incremented when:
     * - close() is called (segment evicted from cache)
     */
    private volatile int generation = 0;

    /**
     * Creates a reference-counted memory segment.
     *
     * @param segment the native memory segment to wrap
     * @param length the logical length of valid data (0 to segment.byteSize())
     * @param onFullyReleased callback invoked when refCount reaches 0 (typically returns to pool)
     * @throws IllegalArgumentException if segment or callback is null
     */
    public RefCountedMemorySegment(MemorySegment segment, int length, BlockReleaser<RefCountedMemorySegment> onFullyReleased) {
        if (segment == null || onFullyReleased == null) {
            throw new IllegalArgumentException("segment and onFullyReleased must not be null");
        }
        this.length = length;
        this.onFullyReleased = onFullyReleased;

        this.slicedSegment = (length < segment.byteSize()) ? segment.asSlice(0, length) : segment;
    }

    /**
     * Increments the reference count (internal use - prefer {@link #tryPin()} for external callers).
     *
     * <p><b>WARNING:</b> This bypasses retirement checks. Use only when you already hold a valid reference
     * (e.g., creating a clone/slice of an IndexInput).
     *
     * @throws IllegalStateException if attempting to increment a fully released segment (refCount was 0)
     */
    public void incRef() {
        int count = (int) REFCOUNT.getAndAdd(this, 1) + 1;
        if (count <= 1) {
            throw new IllegalStateException("Attempted to revive a released segment (refCount=" + count + ")");
        }
    }

    /**
     * Drops a reference to this value without retirement semantics.
     * <p>
     * Atomically decrements the reference count using VarHandle. When the count reaches zero,
     * the segment is returned to the pool via {@link BlockReleaser}.
     * <p>
     * Unlike {@link #close()}, this does not increment the generation counter,
     * making it suitable for releasing ownership without invalidating cached references
     * (e.g., when discarding duplicate loads in bulk operations).
     *
     * @throws IllegalStateException if refCount was already 0 (double-release bug)
     */
    @Override
    public void decRef() {
        int prev = (int) REFCOUNT.getAndAdd(this, -1);
        if (prev == 1) {
            // Last reference dropped - return segment to pool
            onFullyReleased.release(this);
        } else if (prev <= 0) {
            throw new IllegalStateException("decRef underflow (refCount=" + (prev - 1) + ')');
        }
    }

    /**
     * Returns the current reference count (for diagnostics/metrics only).
     *
     * @return the current refCount value (1 = cache only, >1 = cache + active readers)
     */
    public int getRefCount() {
        return refCount; // Direct volatile read
    }

    /**
     * Returns a pre-sliced view of the underlying memory segment containing only valid data.
     * The returned segment has bounds [0, length), hiding any unused capacity.
     *
     * <p><b>IMPORTANT:</b> Only call this while holding a valid pin (after successful {@link #tryPin()}).
     * 
     * @return sliced MemorySegment from offset 0 to {@link #length}
     */
    public MemorySegment segment() {
        return slicedSegment;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int length() {
        return length;
    }

    /**
     * Attempts to acquire a pin (increment refCount) for safe access to this segment.
     * Uses CAS loops for thread-safe concurrent pinning.
     *
     * <p><b>Usage Pattern:</b>
     * <pre>{@code
     * RefCountedMemorySegment seg = cache.get(key);
     * if (seg.tryPin()) {
     *     try {
     *         // Safe to use seg.segment() here
     *     } finally {
     *         seg.unpin();
     *     }
     * }
     * }</pre>
     *
     * @return true if successfully pinned (caller must call {@link #unpin()}), false if retired/released
     */
    @Override
    public boolean tryPin() {
        // Plain volatile read (faster than getVolatile)
        int r = refCount;
        if (r == 0) {
            // Segment already released - should not happen in normal operation
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("tryPin failed: refCount=0 (segment already released)");
            }
            return false;
        }

        // CAS loop to atomically increment refCount
        while (r > 0) {
            if (REFCOUNT.compareAndSet(this, r, r + 1)) {
                return true; // Pin acquired successfully
            }
            r = refCount; // Re-read for next CAS attempt
            Thread.onSpinWait(); // Backoff hint for contention
        }

        // RefCount reached 0 during our CAS attempts
        return false;
    }

    /**
     * Releases a previously acquired pin.
     * Every successful {@link #tryPin()} MUST be paired with exactly one {@code unpin()}.
     *
     * <p>Delegates to {@link #decRef()}.
     */
    @Override
    public void unpin() {
        decRef();
    }

    /**
     * Resets this segment to a fresh state for reuse from the pool.
     * Must be called when a segment is reacquired from the free list.
     *
     * <p><b>IMPORTANT:</b> This method is NOT thread-safe and should only be called
     * by the pool while holding its lock, before the segment is handed out.
     *
     * <p>Resets:
     * <ul>
     *   <li>refCount to 1 (represents new cache/owner reference)</li>
     * </ul>
     *
     * <p><b>Does NOT modify generation</b> - generation is only incremented in {@link #close()} when
     * evicted from cache. This ensures generation changes only when segment ownership changes,
     * not during pool reuse. Same generation value can be reused multiple times as long as the
     * segment remains in the cache.
     */
    public void reset() {
        refCount = 1; // safe under pool lock
    }

    /**
     * Returns the current generation number.
     * Used by BlockSlotTinyCache to detect segment reuse.
     *
     * <p>Ultra-fast volatile read optimized for hot path.
     * Direct field access allows JIT to inline completely.
     *
     * @return current generation counter value
     */
    public int getGeneration() {
        return generation; // Direct volatile read - fastest possible
    }

    /**
     * Closes this cache value by invalidating it and dropping the cache's reference.
     *
     * <p><b>IMPORTANT:</b> This method must be called exactly once per cache entry lifecycle.
     * Caffeine guarantees removalListener is called exactly once, so this is safe.
     * Multiple calls would cause refCount underflow.
     *
     * <p>This method:
     * <ol>
     *   <li>Increments generation (invalidates all cached references in BlockSlotTinyCache)</li>
     *   <li>Calls decRef() (drops cache's reference)</li>
     * </ol>
     *
     * <p>Once generation is incremented, any cached entries with the old
     * generation will fail the generation check and reload from the main cache.
     */
    @Override
    public void close() {
        generation++;
        decRef();
    }

    /**
     * Returns this instance (self-referential for BlockCacheValue contract).
     *
     * @return this RefCountedMemorySegment
     */
    @Override
    public RefCountedMemorySegment value() {
        return this;
    }
}
