/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.block;

import java.lang.foreign.MemorySegment;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.util.concurrent.atomic.AtomicInteger;

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
 *   <li><b>Pin:</b> Reader calls {@link #tryPin()} → refCount incremented (if not retired)</li>
 *   <li><b>Use:</b> Reader accesses {@link #segment()} while pinned</li>
 *   <li><b>Unpin:</b> Reader calls {@link #unpin()} → refCount decremented</li>
 *   <li><b>Eviction:</b> Cache calls {@link #retire()} (marks stale), then {@link #decRef()} (drops cache ref)</li>
 *   <li><b>Release:</b> When refCount reaches 0, {@link BlockReleaser} callback returns segment to pool</li>
 * </ol>
 *
 * <h2>Two-Phase Eviction (prevents stale reads)</h2>
 * <ul>
 *   <li><b>Phase 1 (retire):</b> Sets retired=true → prevents new pins, existing pins remain valid</li>
 *   <li><b>Phase 2 (decRef):</b> Drops cache's reference → segment freed when last reader unpins</li>
 * </ul>
 *
 * <h2>Thread Safety</h2>
 * All public methods are thread-safe using atomic operations (CAS loops for tryPin, AtomicInteger for refCount).
 */
public final class RefCountedMemorySegment implements BlockCacheValue<RefCountedMemorySegment> {

    private static final Logger LOGGER = LogManager.getLogger(RefCountedMemorySegment.class);

    /** Underlying native memory segment holding the decrypted block data. */
    private final MemorySegment segment;

    /** Logical length of valid data in the segment (may be less than segment capacity). */
    private final int length;

    /**
     * Reference counter tracking active users of this segment.
     * - Starts at 1 (cache's initial reference)
     * - Incremented by {@link #tryPin()} when readers acquire the segment
     * - Decremented by {@link #decRef()} when released
     * - When reaches 0, segment is returned to pool via {@link #onFullyReleased}
     */
    private final AtomicInteger refCount = new AtomicInteger(1);

    /**
     * Callback invoked when reference count reaches zero.
     * Typically returns the segment to a memory pool for reuse.
     */
    private final BlockReleaser<RefCountedMemorySegment> onFullyReleased;

    /**
     * VarHandle for atomic CAS operations on the {@link #retired} field.
     */
    private static final VarHandle RETIRED;
    static {
        try {
            RETIRED = MethodHandles.lookup().findVarHandle(RefCountedMemorySegment.class, "retired", boolean.class);
        } catch (IllegalAccessException | NoSuchFieldException e) {
            throw new Error(e);
        }
    }

    /**
     * Retirement flag indicating this segment has been evicted from cache.
     * When true, {@link #tryPin()} will fail, preventing new readers from using stale data.
     * Existing pinned readers can continue using the segment until they unpin.
     */
    private volatile boolean retired = false;

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
        this.segment = segment;
        this.length = length;
        this.onFullyReleased = onFullyReleased;
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
        int count = refCount.incrementAndGet();
        if (count <= 1) {
            throw new IllegalStateException("Attempted to revive a released segment (refCount=" + count + ")");
        }
    }

    /**
     * Decrements the reference count (internal use - prefer {@link #unpin()} for external callers).
     * When refCount reaches 0, invokes {@link #onFullyReleased} to return segment to pool.
     *
     * @throws IllegalStateException if refCount underflows (more decrements than increments)
     */
    public void decRef() {
        int prev = refCount.getAndDecrement();
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
    public AtomicInteger getRefCount() {
        return refCount;
    }

    /**
     * Returns a sliced view of the underlying memory segment containing only valid data.
     * The returned segment has bounds [0, length), hiding any unused capacity.
     *
     * <p><b>IMPORTANT:</b> Only call this while holding a valid pin (after successful {@link #tryPin()}).
     *
     * @return sliced MemorySegment from offset 0 to {@link #length}
     */
    public MemorySegment segment() {
        return segment.asSlice(0, length);
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
        try {
            while (!this.retired) {
                int r = refCount.get();
                if (r == 0) {
                    // Segment fully released but still in cache - should never happen
                    LOGGER.error("tryPin FAILED: refCount=0 (segment released but still in cache), retired={}", this.retired);
                    return false;
                }

                if (refCount.compareAndSet(r, r + 1)) {
                    return true; // Pin acquired successfully
                }

                Thread.onSpinWait(); // Backoff for CAS retry
            }

            // Segment retired - normal eviction path (BlockSlotTinyCache will detect via isRetired())
            LOGGER.debug("tryPin FAILED: segment retired (normal eviction), refCount={}", refCount.get());
            return false;
        } catch (IllegalStateException e) {
            // Race: segment released during pin attempt
            LOGGER.warn("tryPin FAILED: IllegalStateException during pin attempt", e);
            return false;
        }
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
     * Marks this segment as retired without decrementing the reference count.
     * Called by the cache's evictionListener during the first phase of eviction.
     *
     * <p>This prevents new pins ({@link #tryPin()} will fail) while allowing existing
     * readers to continue safely until they unpin. The segment is only freed when
     * refCount reaches 0 (after {@link #decRef()} in phase 2).
     *
     * @return true if this call retired the segment, false if already retired
     */
    public boolean retire() {
        return (boolean) RETIRED.compareAndSet(this, false, true);
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
     *   <li>retired flag to false (allows new pins)</li>
     *   <li>refCount to 1 (represents new cache/owner reference)</li>
     * </ul>
     */
    public void reset() {
        this.retired = false;
        this.refCount.set(1);
    }

    /**
     * Closes this cache value by retiring it and dropping the cache's reference.
     *
     * <p><b>Called exactly once</b> by implementations NOT using two-phase eviction.
     * If using two-phase eviction (evictionListener + removalListener), prefer calling
     * {@link #retire()} and {@link #decRef()} separately.
     *
     * <p>This method combines both phases:
     * <ol>
     *   <li>Sets retired=true (prevents new pins)</li>
     *   <li>Calls decRef() (drops cache's reference)</li>
     * </ol>
     */
    @Override
    public void close() {
        if (retire()) {
            // Drop the cache's reference. Segment freed when last reader unpins.
            decRef();
        }
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

    /**
     * Checks if this segment has been retired from the cache.
     *
     * <p>Used by {@link org.opensearch.index.store.directio.BlockSlotTinyCache} to detect stale
     * cached references after eviction.
     *
     * @return true if retired (segment evicted from cache), false otherwise
     */
    @Override
    public boolean isRetired() {
        return this.retired;
    }
}
