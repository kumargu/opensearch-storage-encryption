/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.block_loader;

import static org.opensearch.index.store.directio.DirectIoConfigs.CACHE_BLOCK_MASK;
import static org.opensearch.index.store.directio.DirectIoConfigs.CACHE_BLOCK_SIZE;
import static org.opensearch.index.store.directio.DirectIoConfigs.CACHE_BLOCK_SIZE_POWER;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.file.Path;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.index.store.async_io.IoUringFile;
import org.opensearch.index.store.block.RefCountedMemorySegment;
import org.opensearch.index.store.cipher.MemorySegmentDecryptor;
import org.opensearch.index.store.iv.KeyIvResolver;
import org.opensearch.index.store.pool.Pool;

/**
 * A {@link BlockLoader} implementation that uses io_uring for asynchronous Direct I/O operations
 * with a registry of persistent file handles.
 *
 * <p>Similar to {@link CryptoDirectIOBlockLoader} but uses io_uring instead of FileChannel.
 * File handles are registered externally (by the directory) and looked up by path on each load.
 *
 * <p>Key features:
 * <ul>
 * <li>Registry-based file handles - maps paths to IoUringFile instances</li>
 * <li>Native async I/O via io_uring (Linux kernel 5.1+)</li>
 * <li>Direct I/O bypassing OS page cache</li>
 * <li>Automatic in-place decryption of loaded blocks</li>
 * <li>Memory pool integration for efficient buffer management</li>
 * </ul>
 *
 * @opensearch.internal
 */
@SuppressWarnings("preview")
public class IoUringBlockLoader implements BlockLoader<RefCountedMemorySegment> {
    private static final Logger LOGGER = LogManager.getLogger(IoUringBlockLoader.class);
    private static final int DIRECT_IO_ALIGNMENT = 512;

    private final Pool<RefCountedMemorySegment> segmentPool;
    private final KeyIvResolver keyIvResolver;

    // Registry of open IoUringFile handles (shared reference from CryptoDirectIODirectory)
    private final ConcurrentHashMap<Path, IoUringFile> fileRegistry;

    /**
     * Constructs a new IoUringBlockLoader.
     *
     * @param segmentPool the memory segment pool for acquiring buffer space
     * @param keyIvResolver the resolver for obtaining encryption keys and IVs
     * @param fileRegistry shared registry from CryptoDirectIODirectory that maps paths to IoUringFile handles
     */
    public IoUringBlockLoader(
        Pool<RefCountedMemorySegment> segmentPool,
        KeyIvResolver keyIvResolver,
        ConcurrentHashMap<Path, IoUringFile> fileRegistry
    ) {
        this.segmentPool = segmentPool;
        this.keyIvResolver = keyIvResolver;
        this.fileRegistry = fileRegistry;
    }

    @Override
    public RefCountedMemorySegment[] load(Path filePath, long startOffset, long blockCount) throws Exception {
        if ((startOffset & CACHE_BLOCK_MASK) != 0) {
            throw new IllegalArgumentException("startOffset must be block-aligned: " + startOffset);
        }

        if (blockCount <= 0) {
            throw new IllegalArgumentException("blockCount must be positive: " + blockCount);
        }

        Path normalized = filePath.toAbsolutePath().normalize();
        IoUringFile ioUringFile = fileRegistry.get(normalized);
        if (ioUringFile == null) {
            throw new IOException("No io_uring file registered for path: " + normalized);
        }

        RefCountedMemorySegment[] result = new RefCountedMemorySegment[(int) blockCount];
        long readLength = blockCount << CACHE_BLOCK_SIZE_POWER;

        try (Arena arena = Arena.ofConfined()) {
            MemorySegment readBuffer = arena.allocate(readLength, DIRECT_IO_ALIGNMENT);

            // Submit async read via io_uring - uses the registered file handle
            CompletableFuture<Integer> readFuture = ioUringFile.readAsync(readBuffer.address(), (int) readLength, startOffset);

            Integer bytesReadObj = readFuture.join();
            if (bytesReadObj == null) {
                throw new RuntimeException("io_uring read returned null at offset " + startOffset);
            }
            long bytesRead = bytesReadObj.longValue();

            if (bytesRead == 0) {
                throw new RuntimeException("EOF or empty read at offset " + startOffset);
            }

            // Decrypt in-place
            MemorySegmentDecryptor
                .decryptInPlace(
                    arena,
                    readBuffer.address(),
                    bytesRead,
                    keyIvResolver.getDataKey().getEncoded(),
                    keyIvResolver.getIvBytes(),
                    startOffset
                );

            // Copy to pooled segments
            int blockIndex = 0;
            long bytesCopied = 0;

            try {
                while (blockIndex < blockCount && bytesCopied < bytesRead) {
                    RefCountedMemorySegment handle = segmentPool.tryAcquire(10, TimeUnit.MILLISECONDS);
                    if (handle == null) {
                        throw new BlockLoader.PoolAcquireFailedException("Failed to acquire memory segment from pool after 10ms timeout");
                    }

                    MemorySegment pooled = handle.segment();
                    int remaining = (int) (bytesRead - bytesCopied);
                    int toCopy = Math.min(CACHE_BLOCK_SIZE, remaining);

                    if (toCopy > 0) {
                        MemorySegment.copy(readBuffer, bytesCopied, pooled, 0, toCopy);
                    }

                    result[blockIndex++] = handle;
                    bytesCopied += toCopy;
                }
            } catch (InterruptedException e) {
                releaseHandles(result, blockIndex);
                Thread.currentThread().interrupt();
                throw new BlockLoader.BlockLoadFailedException("Interrupted while acquiring pool segments", e);
            }

            return result;

        } catch (Exception e) {
            LOGGER.error("io_uring bulk read failed: path={} offset={} blocks={}", normalized, startOffset, blockCount, e);
            throw e;
        }
    }

    private void releaseHandles(RefCountedMemorySegment[] handles, int upTo) {
        for (int i = 0; i < upTo; i++) {
            if (handles[i] != null) {
                handles[i].close();
            }
        }
    }
}
