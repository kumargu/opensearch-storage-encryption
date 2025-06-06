/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.hybrid;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Provider;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.store.FileSwitchDirectory;
import org.apache.lucene.store.IOContext;
import org.apache.lucene.store.IOContext.Context;
import org.apache.lucene.store.IndexInput;
import org.apache.lucene.store.LockFactory;
import org.opensearch.common.util.io.IOUtils;
import org.opensearch.index.store.iv.KeyIvResolver;
import org.opensearch.index.store.mmap.CryptoMMapDirectory;
import org.opensearch.index.store.mmap.CryptoMMapDirectoryLargeFiles;
import org.opensearch.index.store.niofs.CryptoNIOFSDirectory;

public class HybridCryptoDirectory extends CryptoNIOFSDirectory {
    private static final Logger LOGGER = LogManager.getLogger(CryptoNIOFSDirectory.class);

    private final CryptoMMapDirectory delegate;
    private final CryptoMMapDirectoryLargeFiles cryptoMMapDirectoryLargeFilesDelegate;
    private final Set<String> nioExtensions;

    // File size thresholds for special files only
    private static final long MEDIUM_FILE_THRESHOLD = 10 * 1024 * 1024; // 10MB

    // Only these extensions get special routing - everything else goes to NIOFS
    private final Set<String> specialExtensions;

    public HybridCryptoDirectory(
        LockFactory lockFactory,
        CryptoMMapDirectory delegate,
        CryptoMMapDirectoryLargeFiles cryptoMMapDirectoryLargeFilesDelegate,
        Provider provider,
        KeyIvResolver keyIvResolver,
        Set<String> nioExtensions
    )
        throws IOException {
        super(lockFactory, delegate.getDirectory(), provider, keyIvResolver);
        this.delegate = delegate;
        this.cryptoMMapDirectoryLargeFilesDelegate = cryptoMMapDirectoryLargeFilesDelegate;
        this.nioExtensions = nioExtensions;
        // Only these files get special treatment
        this.specialExtensions = Set.of("kdd", "kdi", "kdm", "cfs", "tip", "tim", "tmd");
    }

    @Override
    public IndexInput openInput(String name, IOContext context) throws IOException {
        ensureOpen();
        ensureCanRead(name);

        String extension = FileSwitchDirectory.getExtension(name);

        // If not a special extension, always use NIOFS
        if (!specialExtensions.contains(extension)) {
            return super.openInput(name, context);
        }

        // Special routing for key file types
        return routeSpecialFile(name, extension, context);
    }

    private IndexInput routeSpecialFile(String name, String extension, IOContext context) throws IOException {
        Path file = getDirectory().resolve(name);
        long fileSize = Files.size(file);

        // MERGE context: Always use NIOFS for sequential, one-time access
        if (context.context() == Context.MERGE) {
            LOGGER.info("Routing {} to NIOFS for merge operation", name);
            return super.openInput(name, context);
        }

        // FLUSH context: New segment creation - consider future access patterns
        if (context.context() == Context.FLUSH) {
            LOGGER.info("Routing for flush operation", name);

            // For files that will be accessed randomly after flush, prepare them for MMap
            // Exception: large files should avoid memory pressure during flush
            if (("kdd".equals(extension) || "cfs".equals(extension)) && fileSize > MEDIUM_FILE_THRESHOLD) {
                LOGGER.debug("Routing large {} to NIOFS during flush to avoid memory pressure", name);
                return super.openInput(name, context);
            }
            // Term files and tree files benefit from MMap even during flush
            if ("tim".equals(extension)
                || "tip".equals(extension)
                || "tmd".equals(extension)
                || "kdi".equals(extension)
                || "kdm".equals(extension)) {
                LOGGER.debug("Routing {} to MMap during flush for future random access", name);
                return delegate.openInput(name, context);
            }
            // Small KDD and CFS files can use MMap during flush
            LOGGER.debug("Routing small {} to MMap during flush", name);
            return delegate.openInput(name, context);
        }

        // Route based on file type and access patterns
        switch (extension) {
            case "tim", "tip", "tmd" -> {
                // Term dictionary files: Random access to small blocks (~2KB)
                // Always use MMap for optimal performance regardless of size
                LOGGER.debug("Routing term file {} to MMap for random small block access", name);
                return delegate.openInput(name, context);
            }
            case "kdi" -> {
                // BKD tree index: Random access, typically loaded into heap
                // Always use MMap for optimal performance
                LOGGER.debug("Routing KDI {} to MMap for tree traversal", name);
                return delegate.openInput(name, context);
            }
            case "kdm" -> {
                // BKD tree metadata: Small file, infrequent access
                // Use MMap for simplicity
                LOGGER.debug("Routing KDM {} to MMap", name);
                return delegate.openInput(name, context);
            }

            case "kdd" -> {
                // BKD tree leaf data: Hybrid access pattern
                // Random access to leaf blocks, sequential within blocks
                if (fileSize < MEDIUM_FILE_THRESHOLD) {
                    LOGGER.debug("Routing small/medium KDD {} to MMap for hybrid access", name);
                    return delegate.openInput(name, context);
                } else {
                    LOGGER.debug("Routing large KDD {} to specialized large file handler", name);
                    return cryptoMMapDirectoryLargeFilesDelegate.openInput(name, context);
                }
            }

            case "cfs" -> {
                // Compound files: Mixed access patterns, can be very large
                if (fileSize > MEDIUM_FILE_THRESHOLD) {
                    LOGGER.debug("Routing large compound file {} to specialized handler", name);
                    return cryptoMMapDirectoryLargeFilesDelegate.openInput(name, context);
                } else {
                    LOGGER.debug("Routing compound file {} to MMap", name);
                    return delegate.openInput(name, context);
                }
            }

            default -> {
                // Should not reach here given our specialExtensions check
                return super.openInput(name, context);
            }
        }
    }

    private boolean useDelegate(String name) {
        String extension = FileSwitchDirectory.getExtension(name);

        if (name.endsWith(".tmp") || name.contains("segments_")) {
            return false;
        }

        // [cfe, tvd, fnm, nvm, write.lock, dii, pay, segments_N, pos, si, fdt, tvx, liv, dvm, fdx, vem]
        boolean result = extension == null || !nioExtensions.contains(extension);
        return result;
    }

    @Override
    public void close() throws IOException {
        IOUtils.close(super::close, delegate);
    }

    public CryptoMMapDirectory getDelegate() {
        return delegate;
    }
}
