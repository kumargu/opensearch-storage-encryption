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
 * <p>Key features:
 * <ul>
 *   <li>Registry-based file handles (shared across readers)</li>
 *   <li>Native async I/O via io_uring</li>
 *   <li>Direct I/O bypassing OS page cache</li>
 *   <li>In-place decryption</li>
 *   <li>Memory pool integration</li>
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
    private final ConcurrentHashMap<Path, IoUringFile> fileRegistry;

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
        if ((startOffset & CACHE_BLOCK_MASK) != 0)
            throw new IllegalArgumentException("startOffset must be block-aligned: " + startOffset);

        if (blockCount <= 0)
            throw new IllegalArgumentException("blockCount must be positive: " + blockCount);

        Path normalized = filePath.toAbsolutePath().normalize();
        IoUringFile ioUringFile = fileRegistry.get(normalized);
        if (ioUringFile == null)
            throw new IOException("No io_uring file registered for path: " + normalized);

        long readLength = blockCount << CACHE_BLOCK_SIZE_POWER;
        if ((readLength & (DIRECT_IO_ALIGNMENT - 1)) != 0)
            throw new IllegalArgumentException("readLength must be 512-byte aligned: " + readLength);

        RefCountedMemorySegment[] result = new RefCountedMemorySegment[(int) blockCount];

        try (Arena arena = Arena.ofConfined()) {
            MemorySegment readBuffer = arena.allocate(readLength, DIRECT_IO_ALIGNMENT);

            CompletableFuture<Integer> readFuture = ioUringFile.readAsync(readBuffer.address(), (int) readLength, startOffset);

            Integer bytesReadObj = readFuture.join();
            if (bytesReadObj == null || bytesReadObj <= 0)
                throw new IOException("EOF or failed read at offset " + startOffset);

            long bytesRead = bytesReadObj;

            // In-place decryption
            MemorySegmentDecryptor
                .decryptInPlace(
                    readBuffer.address(),
                    bytesRead,
                    keyIvResolver.getDataKey().getEncoded(),
                    keyIvResolver.getIvBytes(),
                    startOffset
                );

            copyToPool(readBuffer, bytesRead, result, blockCount);
            return result;

        } catch (Exception e) {
            LOGGER.error("io_uring bulk read failed: path={} offset={} blocks={}", normalized, startOffset, blockCount, e);
            throw e;
        }
    }

    @Override
    public CompletableFuture<RefCountedMemorySegment[]> loadAsync(Path filePath, long startOffset, long blockCount) {
        if ((startOffset & CACHE_BLOCK_MASK) != 0)
            return CompletableFuture.failedFuture(new IllegalArgumentException("startOffset must be block-aligned: " + startOffset));

        if (blockCount <= 0)
            return CompletableFuture.failedFuture(new IllegalArgumentException("blockCount must be positive: " + blockCount));

        Path normalized = filePath.toAbsolutePath().normalize();
        IoUringFile ioUringFile = fileRegistry.get(normalized);
        if (ioUringFile == null)
            return CompletableFuture.failedFuture(new IOException("No io_uring file registered for path: " + normalized));

        long readLength = blockCount << CACHE_BLOCK_SIZE_POWER;
        if ((readLength & (DIRECT_IO_ALIGNMENT - 1)) != 0)
            return CompletableFuture.failedFuture(new IllegalArgumentException("readLength must be 512-byte aligned: " + readLength));

        RefCountedMemorySegment[] result = new RefCountedMemorySegment[(int) blockCount];
        // Use shared arena since it escapes the current thread scope (async completion)
        Arena arena = Arena.ofShared();
        MemorySegment readBuffer = arena.allocate(readLength, DIRECT_IO_ALIGNMENT);

        CompletableFuture<Integer> readFuture = ioUringFile.readAsync(readBuffer.address(), (int) readLength, startOffset);

        return readFuture.handle((bytesReadObj, ex) -> {
            try (arena) {
                if (ex != null)
                    throw new IOException("io_uring read failed", ex);
                if (bytesReadObj == null || bytesReadObj <= 0)
                    throw new IOException("EOF or empty read at offset " + startOffset);

                long bytesRead = bytesReadObj;

                MemorySegmentDecryptor
                    .decryptInPlace(
                        readBuffer.address(),
                        bytesRead,
                        keyIvResolver.getDataKey().getEncoded(),
                        keyIvResolver.getIvBytes(),
                        startOffset
                    );
                copyToPool(readBuffer, bytesRead, result, blockCount);
                return result;

            } catch (Exception e2) {
                LOGGER.error("io_uring async load failed: path={} offset={} blocks={}", normalized, startOffset, blockCount, e2);
                throw new RuntimeException(e2);
            }
        });
    }

    private void copyToPool(MemorySegment readBuffer, long bytesRead, RefCountedMemorySegment[] result, long blockCount) {
        int blockIndex = 0;
        long bytesCopied = 0;

        try {
            while (blockIndex < blockCount && bytesCopied < bytesRead) {
                RefCountedMemorySegment handle = segmentPool.tryAcquire(10, TimeUnit.MILLISECONDS);
                if (handle == null)
                    throw new BlockLoader.PoolAcquireFailedException("Timeout acquiring memory segment from pool");

                MemorySegment pooled = handle.segment();
                int toCopy = (int) Math.min(CACHE_BLOCK_SIZE, bytesRead - bytesCopied);

                MemorySegment.copy(readBuffer, bytesCopied, pooled, 0, toCopy);
                result[blockIndex++] = handle;
                bytesCopied += toCopy;
            }
        } catch (InterruptedException e) {
            // Release already acquired segments
            for (int i = 0; i < blockIndex; i++) {
                if (result[i] != null) {
                    result[i].close();
                }
            }
            Thread.currentThread().interrupt();
            throw new BlockLoader.BlockLoadFailedException("Interrupted while acquiring pool segments", e);
        }
    }
}
