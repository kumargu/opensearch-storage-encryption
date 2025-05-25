/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.hybrid;

import java.io.IOException;
import java.security.Provider;
import java.util.Set;

import org.apache.lucene.store.FileSwitchDirectory;
import org.apache.lucene.store.IOContext;
import org.apache.lucene.store.IndexInput;
import org.apache.lucene.store.LockFactory;
import org.apache.lucene.store.MMapDirectory;
import org.opensearch.common.util.io.IOUtils;
import org.opensearch.index.store.iv.KeyIvResolver;
import org.opensearch.index.store.mmap.CryptoMMapDirectory;
import org.opensearch.index.store.mmap.MMapCryptoIndexInput;
import org.opensearch.index.store.niofs.CryptoNIOFSDirectory;

public class HybridCryptoDirectory extends CryptoNIOFSDirectory {

    private final CryptoMMapDirectory delegate;
    private final MMapDirectory mmapDirectoryDelegate;
    private final Set<String> nioExtensions;
    private Set<String> mmapDirectoryExtensions;

    public HybridCryptoDirectory(
        LockFactory lockFactory,
        CryptoMMapDirectory delegate,
        MMapDirectory mmapDirectoryDelegate,
        Provider provider,
        KeyIvResolver keyIvResolver,
        Set<String> nioExtensions
    )
        throws IOException {
        super(lockFactory, delegate.getDirectory(), provider, keyIvResolver);
        this.delegate = delegate;
        this.mmapDirectoryDelegate = mmapDirectoryDelegate;
        this.nioExtensions = Set
            .of(
                "cfe",
                "tvd",
                "fnm",
                "nvm",
                "write.lock",
                "dii",
                "pay",
                "segments_N",
                "pos",
                "si",
                "fdt",
                "tvx",
                "liv",
                "dvm",
                "fdx",
                "vem",
                "fdm",
                "kdm",
                "kdi",
                "psm",
                "tmd",
                "tip",
                "nvd",
                "cfs",
                "tim"
            );
        this.mmapDirectoryExtensions = Set.of("doc", "dvd", "kdd");
    }

    @Override
    public IndexInput openInput(String name, IOContext context) throws IOException {
        ensureOpen();
        ensureCanRead(name);

        String extension = FileSwitchDirectory.getExtension(name);
        if (extension != null && mmapDirectoryExtensions.contains(extension)) {
            // Route to MMapCryptoIndexInput directly
            return new MMapCryptoIndexInput(
                "MMapCryptoIndexInput(path=\"" + name + "\")",
                mmapDirectoryDelegate.openInput(name, context),
                keyIvResolver
            );
        } else if (useDelegate(name)) {
            // Route to CryptoMMapDirectory (decrypt + mmap)
            return delegate.openInput(name, context);
        } else {
            // Default to CryptoNIOFSDirectory
            return super.openInput(name, context);
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
