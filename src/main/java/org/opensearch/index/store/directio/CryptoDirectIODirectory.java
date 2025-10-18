/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.directio;

import static org.opensearch.index.store.directio.DirectIoConfigs.CACHE_BLOCK_SIZE;
import static org.opensearch.index.store.directio.DirectIoConfigs.CACHE_BLOCK_SIZE_POWER;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.Provider;
import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.store.FSDirectory;
import org.apache.lucene.store.IOContext;
import org.apache.lucene.store.IndexInput;
import org.apache.lucene.store.IndexOutput;
import org.apache.lucene.store.LockFactory;
import org.opensearch.common.SuppressForbidden;
import org.opensearch.index.store.async_io.IoUringFile;
import org.opensearch.index.store.block.RefCountedMemorySegment;
import org.opensearch.index.store.block_cache.BlockCache;
import org.opensearch.index.store.block_cache.CaffeineBlockCache;
import org.opensearch.index.store.block_cache.FileBlockCacheKey;
import org.opensearch.index.store.iv.KeyIvResolver;
import org.opensearch.index.store.pool.Pool;
import org.opensearch.index.store.read_ahead.ReadaheadContext;
import org.opensearch.index.store.read_ahead.ReadaheadManager;
import org.opensearch.index.store.read_ahead.Worker;
import org.opensearch.index.store.read_ahead.impl.ReadaheadManagerImpl;

import io.netty.channel.IoEventLoopGroup;

/**
 * A high-performance FSDirectory implementation that combines Direct I/O operations with encryption.
 * 
 * <p>This directory provides:
 * <ul>
 * <li>Direct I/O operations bypassing the OS page cache for better memory control</li>
 * <li>Block-level caching with memory segment pools for efficient memory management</li>
 * <li>Transparent encryption/decryption using OpenSSL native implementations</li>
 * <li>Read-ahead optimizations for sequential access patterns</li>
 * <li>Automatic cache invalidation on file deletion</li>
 * </ul>
 * 
 * <p>The directory uses {@link BufferIOWithCaching} for output operations which encrypts
 * data before writing to disk and caches plaintext blocks for read operations. Input
 * operations use {@link CachedMemorySegmentIndexInput} with a multi-level cache hierarchy
 * including {@link BlockSlotTinyCache} for L1 caching.
 * 
 * <p>Note: Some file types (segments files and .si files) fall back to the parent
 * directory implementation to avoid compatibility issues.
 * 
 * @opensearch.internal
 */
@SuppressForbidden(reason = "uses custom DirectIO")
public final class CryptoDirectIODirectory extends FSDirectory {
    private static final Logger LOGGER = LogManager.getLogger(CryptoDirectIODirectory.class);
    private final AtomicLong nextTempFileCounter = new AtomicLong();

    private final Pool<RefCountedMemorySegment> memorySegmentPool;
    private final BlockCache<RefCountedMemorySegment> blockCache;
    private final Worker readAheadworker;
    private final KeyIvResolver keyIvResolver;
    private final IoEventLoopGroup ioEventLoopGroup;
    private final ConcurrentHashMap<Path, IoUringFile> ioUringFileRegistry;

    /**
     * Creates a new CryptoDirectIODirectory with io_uring support.
     *
     * @param path the directory path
     * @param lockFactory the lock factory for coordinating access
     * @param provider the security provider for cryptographic operations (unused, kept for compatibility)
     * @param keyIvResolver resolver for encryption keys and initialization vectors
     * @param memorySegmentPool pool for managing off-heap memory segments
     * @param blockCache cache for storing decrypted blocks (must use IoUringBlockLoader)
     * @param worker background worker for read-ahead operations
     * @param ioEventLoopGroup io_uring event loop group for lifecycle management
     * @param ioUringFileRegistry shared registry mapping file paths to IoUringFile handles
     * @throws IOException if the directory cannot be created or accessed
     */
    public CryptoDirectIODirectory(
        Path path,
        LockFactory lockFactory,
        Provider provider,
        KeyIvResolver keyIvResolver,
        Pool<RefCountedMemorySegment> memorySegmentPool,
        BlockCache<RefCountedMemorySegment> blockCache,
        Worker worker,
        IoEventLoopGroup ioEventLoopGroup,
        ConcurrentHashMap<Path, IoUringFile> ioUringFileRegistry
    )
        throws IOException {
        super(path, lockFactory);
        this.keyIvResolver = keyIvResolver;
        this.memorySegmentPool = memorySegmentPool;
        this.blockCache = blockCache;
        this.readAheadworker = worker;
        this.ioEventLoopGroup = ioEventLoopGroup;
        this.ioUringFileRegistry = ioUringFileRegistry;
        startCacheStatsTelemetry();
    }

    @Override
    public IndexInput openInput(String name, IOContext context) throws IOException {
        ensureOpen();
        ensureCanRead(name);

        Path file = getDirectory().resolve(name);
        long size = Files.size(file);
        if (size == 0) {
            throw new IOException("Cannot open empty file: " + file);
        }

        // Setup read-ahead
        ReadaheadManager readAheadManager = new ReadaheadManagerImpl(readAheadworker);
        ReadaheadContext readAheadContext = readAheadManager.register(file, size);
        BlockSlotTinyCache pinRegistry = new BlockSlotTinyCache(blockCache, file, size);

        LOGGER.debug("Opened io_uring IndexInput: {}", file);

        return CachedMemorySegmentIndexInput
            .newInstance(
                "IoUringIndexInput(path=\"" + file + "\")",
                file,
                size,
                blockCache,  // Use the shared cache directly
                readAheadManager,
                readAheadContext,
                pinRegistry
            );
    }

    @Override
    public IndexOutput createOutput(String name, IOContext context) throws IOException {
        if (name.contains("segments_") || name.endsWith(".si")) {
            return super.createOutput(name, context);
        }

        ensureOpen();
        Path path = directory.resolve(name);
        OutputStream fos = Files.newOutputStream(path, StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW);

        IoUringFile ioUringFile = IoUringFile
            .open(path.toFile(), this.ioEventLoopGroup.next(), IoUringFile.getDirectOpenOption(), StandardOpenOption.READ)
            .join();
        Path normalized = path.toAbsolutePath().normalize();
        ioUringFileRegistry.put(normalized, ioUringFile);

        return new BufferIOWithCaching(
            name,
            path,
            fos,
            this.keyIvResolver.getDataKey().getEncoded(),
            keyIvResolver.getIvBytes(),
            this.memorySegmentPool,
            this.blockCache
        );

    }

    @Override
    public IndexOutput createTempOutput(String prefix, String suffix, IOContext context) throws IOException {
        if (prefix.contains("segments_") || prefix.endsWith(".si")) {
            return super.createTempOutput(prefix, suffix, context);
        }

        ensureOpen();
        String name = getTempFileName(prefix, suffix, nextTempFileCounter.getAndIncrement());
        Path path = directory.resolve(name);
        OutputStream fos = Files.newOutputStream(path, StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW);

        IoUringFile ioUringFile = IoUringFile
            .open(path.toFile(), this.ioEventLoopGroup.next(), IoUringFile.getDirectOpenOption(), StandardOpenOption.READ)
            .join();

        // Register in the shared registry (loader will look it up by path)
        Path normalized = path.toAbsolutePath().normalize();
        ioUringFileRegistry.put(normalized, ioUringFile);

        return new BufferIOWithCaching(
            name,
            path,
            fos,
            this.keyIvResolver.getDataKey().getEncoded(),
            keyIvResolver.getIvBytes(),
            this.memorySegmentPool,
            this.blockCache
        );
    }

    // only close resources owned by this directory type.
    // the actual directory is closed only once (see HybridCryptoDirectory.java)
    @Override
    @SuppressWarnings("ConvertToTryWithResources")
    public synchronized void close() throws IOException {
        try {
            readAheadworker.close();
        } finally {
            try {
                // Close all io_uring file handles
                for (var entry : ioUringFileRegistry.entrySet()) {
                    try {
                        entry.getValue().close();
                        LOGGER.debug("Closed io_uring file: {}", entry.getKey());
                    } catch (Exception e) {
                        LOGGER.warn("Failed to close io_uring file: {}", entry.getKey(), e);
                    }
                }
                ioUringFileRegistry.clear();
            } finally {
                // Shutdown io_uring event loop group
                if (ioEventLoopGroup != null) {
                    try {
                        ioEventLoopGroup.shutdownGracefully().sync();
                        LOGGER.debug("Shutdown io_uring event loop group");
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        LOGGER.warn("Interrupted while shutting down io_uring event loop group", e);
                    } catch (Exception e) {
                        LOGGER.warn("Failed to shutdown io_uring event loop group", e);
                    }
                }
            }
        }
    }

    @Override
    public void deleteFile(String name) throws IOException {
        Path file = getDirectory().resolve(name);
        Path normalized = file.toAbsolutePath().normalize();

        // Close and remove io_uring file handle if open
        IoUringFile ioUringFile = ioUringFileRegistry.remove(normalized);
        if (ioUringFile != null) {
            try {
                ioUringFile.close();
                LOGGER.debug("Closed io_uring file on delete: {}", normalized);
            } catch (Exception e) {
                LOGGER.warn("Failed to close io_uring file on delete: {}", normalized, e);
            }
        }

        // Invalidate cache entries
        if (blockCache != null) {
            try {
                long fileSize = Files.size(file);
                if (fileSize > 0) {
                    final int totalBlocks = (int) ((fileSize + CACHE_BLOCK_SIZE - 1) >>> CACHE_BLOCK_SIZE_POWER);
                    for (int i = 0; i < totalBlocks; i++) {
                        final long blockOffset = (long) i << CACHE_BLOCK_SIZE_POWER;
                        FileBlockCacheKey key = new FileBlockCacheKey(file, blockOffset);
                        blockCache.invalidate(key);
                    }
                }
            } catch (IOException e) {
                LOGGER.warn("Failed to get file size for cache invalidation", e);
            }
        }

        super.deleteFile(name);
    }

    private void logCacheAndPoolStats() {
        try {

            if (blockCache instanceof CaffeineBlockCache) {
                String cacheStats = ((CaffeineBlockCache<?, ?>) blockCache).cacheStats();
                LOGGER.info("{}", cacheStats);
            }

        } catch (Exception e) {
            LOGGER.warn("Failed to log cache/pool stats", e);
        }
    }

    private void startCacheStatsTelemetry() {
        Thread loggerThread = new Thread(() -> {
            while (true) {
                try {
                    Thread.sleep(Duration.ofMinutes(2));
                    logCacheAndPoolStats();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                } catch (Throwable t) {
                    LOGGER.warn("Error in collecting cache stats", t);
                }
            }
        });

        loggerThread.setDaemon(true);
        loggerThread.setName("DirectIOBufferPoolStatsLogger");
        loggerThread.start();
    }
}
