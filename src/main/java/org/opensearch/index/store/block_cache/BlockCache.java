/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.block_cache;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * Generic block cache interface for storing and retrieving blocks of data.
 * 
 * <p>This cache provides efficient storage and retrieval of file blocks with support for
 * asynchronous loading, bulk operations, and cache invalidation. The cache is parameterized
 * by the type {@code T} which represents the cached block data.
 *
 * <p>Implementations should be thread-safe and handle concurrent access appropriately.
 *
 * @param <T> the type of cached block data
 * @opensearch.internal
 */
public interface BlockCache<T> {

    /**
     * Returns the block if cached, or null if absent.
     *
     * @param key the cache key identifying the block
     * @return the cached block value, or null if not present
     */
    BlockCacheValue<T> get(BlockCacheKey key);

    /**
     * Returns the block, loading it via {@code BlockLoader} if absent.
     * 
     * @param key the cache key identifying the block
     * @return the block value, either from cache or newly loaded
     * @throws IOException if the block cannot be loaded
     */
    BlockCacheValue<T> getOrLoad(BlockCacheKey key) throws IOException;

    /**
     * Put a block into the cache.
     *
     * @param key the cache key for the block
     * @param value the block value to cache
     */
    void put(BlockCacheKey key, BlockCacheValue<T> value);

    /**
     * Evict a block from the cache.
     *
     * @param key the cache key for the block to evict
     */
    void invalidate(BlockCacheKey key);

    /**
     * Evict all blocks for a given normalized file path.
     *
     * @param normalizedFilePath the file path whose blocks should be evicted
     */
    void invalidate(Path normalizedFilePath);

    /**
     * Clear all blocks from the cache.
     */
    void clear();

    /**
     * Bulk load multiple blocks efficiently using a single I/O operation.
     * Similar to getOrLoad() but for a contiguous range of blocks.
     *
     * @param filePath file to read from
     * @param startOffset starting file offset (should be block-aligned)
     * @param blockCount number of blocks to read
     * @return map of cache keys to cache values for blocks that were successfully loaded into the cache
     * @throws IOException if loading fails (including specific BlockLoader exceptions)
     */
    Map<BlockCacheKey, BlockCacheValue<T>> loadBulk(Path filePath, long startOffset, long blockCount) throws IOException;

    /**
     * Asynchronously bulk load multiple blocks for read-ahead purposes.
     * Blocks are loaded into the cache asynchronously without blocking the caller.
     *
     * <p>The async operation chain:
     * <ol>
     * <li>Submit async read to I/O subsystem (e.g., io_uring)</li>
     * <li>Decrypt data when read completes</li>
     * <li>Populate cache with decrypted blocks</li>
     * </ol>
     *
     * <p>The returned CompletableFuture completes when all blocks are loaded into cache.
     * Callers can ignore the future for fire-and-forget behavior, or use it to track completion.
     *
     * @param filePath file to read from
     * @param startOffset starting file offset (should be block-aligned)
     * @param blockCount number of blocks to read
     * @return CompletableFuture that completes when cache population finishes (successfully or with error)
     */
    CompletableFuture<Void> loadBulkAsync(Path filePath, long startOffset, long blockCount);

    /**
     * Returns cache statistics as a formatted string.
     *
     * @return string representation of cache statistics including hit/miss ratios, sizes, etc.
     */
    String cacheStats();
}
