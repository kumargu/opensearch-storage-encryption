/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.mmap;

import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;

import org.apache.lucene.store.ByteBuffersDataOutput;
import org.apache.lucene.store.ByteBuffersIndexInput;
import org.apache.lucene.store.FilterIndexInput;
import org.apache.lucene.store.IndexInput;
import org.opensearch.index.store.cipher.OpenSslPanamaCipher;
import org.opensearch.index.store.iv.KeyIvResolver;

public final class MMapCryptoIndexInput extends FilterIndexInput {

    private final KeyIvResolver keyResolver;
    private final ByteBuffersDataOutput.ByteBufferRecycler recycler;

    public MMapCryptoIndexInput(String resourceDescription, IndexInput in, KeyIvResolver keyResolver) {
        super(resourceDescription, in);
        this.keyResolver = keyResolver;
        this.recycler = new ByteBuffersDataOutput.ByteBufferRecycler(ByteBuffer::allocate);
    }

    @Override
    public IndexInput clone() {
        return new MMapCryptoIndexInput("clone", in.clone(), keyResolver);
    }

    @Override
    public byte readByte() throws IOException {
        try {
            byte b = in.readByte();
            byte[] decrypted = OpenSslPanamaCipher
                .decrypt(keyResolver.getDataKey().getEncoded(), keyResolver.getIvBytes(), new byte[] { b }, getFilePointer() - 1);
            return decrypted[0];
        } catch (Throwable ex) {
            throw new IOException("Failed to read single byte", ex);
        }
    }

    @Override
    public void readBytes(byte[] b, int offset, int len) throws IOException {
        try {
            byte[] tmp = new byte[len];
            in.readBytes(tmp, 0, len);
            byte[] decrypted = OpenSslPanamaCipher
                .decrypt(keyResolver.getDataKey().getEncoded(), keyResolver.getIvBytes(), tmp, getFilePointer() - len);
            System.arraycopy(decrypted, 0, b, offset, len);
        } catch (Throwable ex) {
            throw new IOException("Failed to read single byte", ex);
        }
    }

    @Override
    public void skipBytes(long numBytes) throws IOException {
        seek(getFilePointer() + numBytes);
    }

    @Override
    public void seek(long pos) throws IOException {
        if (pos < 0 || pos > length()) {
            throw new EOFException("seek past EOF: pos=" + pos + ", length=" + length());
        }
        in.seek(pos);
    }

    @Override
    public IndexInput slice(String sliceDescription, long offset, long length) throws IOException {
        if (length > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("Slice too large: " + length);
        }

        ByteBuffersDataOutput output;
        try (IndexInput delegate = in.slice(sliceDescription, offset, length)) {
            ByteBuffer temp = recycler.allocate(16 * 1024);
            ByteBuffer tempOut = recycler.allocate(16 * 1024);
            output = new ByteBuffersDataOutput(length);
            long remaining = length;
            long position = offset;
            while (remaining > 0) {
                final int chunk = (int) Math.min(remaining, temp.capacity());
                delegate.readBytes(temp.array(), 0, chunk, true);

                byte[] decrypted;
                try {
                    decrypted = OpenSslPanamaCipher
                        .decrypt(
                            keyResolver.getDataKey().getEncoded(),
                            keyResolver.getIvBytes(),
                            temp.rewind().limit(chunk).array(),
                            position
                        );
                } catch (Throwable t) {
                    throw new IOException("Failed to decrypt slice chunk", t);
                }

                output.writeBytes(ByteBuffer.wrap(decrypted));
                position += chunk;
                remaining -= chunk;
            }
            recycler.reuse(temp);
            recycler.reuse(tempOut);
        }
        return new ByteBuffersIndexInput(output.toDataInput(), sliceDescription);
    }

    @Override
    public void close() throws IOException {
        in.close();
    }
}
