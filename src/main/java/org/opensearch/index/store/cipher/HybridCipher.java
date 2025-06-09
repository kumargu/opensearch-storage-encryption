/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.cipher;

import java.lang.foreign.MemorySegment;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Hybrid cipher implementation that can use either:
 * 1. Native OpenSSL via Panama (for large operations)
 * 2. Java Cipher API via ByteBuffer (for small operations, better JIT optimization)
 */

@SuppressWarnings("preview")
public class HybridCipher {

    private final Provider jceProvider;
    private final ThreadLocal<Cipher> cipherPool;

    public HybridCipher() {
        this.jceProvider = Security.getProvider("SunJCE");
        this.cipherPool = ThreadLocal.withInitial(() -> {
            try {
                return Cipher.getInstance("AES/CTR/NoPadding", jceProvider);
            } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
                throw new RuntimeException("Failed to create cipher", e);
            }
        });
    }

    /**
     * Decrypt in-place using the most appropriate method based on size
     * @throws Throwable 
     */
    public void decryptInPlace(long addr, long length, byte[] key, byte[] iv, long fileOffset) throws Throwable {
        decryptInPlaceViaCipher(addr, (int) length, key, iv, fileOffset);
    }

    /**
     * Decrypt small regions using Java Cipher API and ByteBuffer
     * This avoids JNI overhead for small operations
     * Uses your proven chunked approach
     */
    private void decryptInPlaceViaCipher(long addr, int length, byte[] key, byte[] iv, long fileOffset) throws Exception {

        // Get thread-local cipher
        Cipher cipher = cipherPool.get();

        // Initialize cipher for this position (your proven approach)
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        byte[] ivCopy = Arrays.copyOf(iv, iv.length);

        int blockOffset = (int) (fileOffset / CipherFactory.AES_BLOCK_SIZE_BYTES);
        for (int i = CipherFactory.IV_ARRAY_LENGTH - 1; i >= CipherFactory.IV_ARRAY_LENGTH - CipherFactory.COUNTER_SIZE_BYTES; i--) {
            ivCopy[i] = (byte) blockOffset;
            blockOffset >>>= Byte.SIZE;
        }

        cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(ivCopy));

        // Skip partial block offset if needed
        int bytesToSkip = (int) (fileOffset % CipherFactory.AES_BLOCK_SIZE_BYTES);
        if (bytesToSkip > 0) {
            cipher.update(new byte[bytesToSkip]);
        }

        // Create memory segment and ByteBuffer
        MemorySegment segment = MemorySegment.ofAddress(addr).reinterpret(length);
        ByteBuffer buffer = segment.asByteBuffer();

        // Use your chunked decryption approach
        final int CHUNK_SIZE = Math.min(8192, length); // Smaller chunks for small operations
        byte[] chunk = new byte[CHUNK_SIZE];

        int position = 0;
        while (position < buffer.capacity()) {
            int size = Math.min(CHUNK_SIZE, buffer.capacity() - position);
            buffer.position(position);
            buffer.get(chunk, 0, size);

            byte[] decrypted;
            if (position + size >= buffer.capacity()) {
                // Last chunk
                decrypted = cipher.doFinal(chunk, 0, size);
            } else {
                decrypted = cipher.update(chunk, 0, size);
            }

            if (decrypted != null) {
                buffer.position(position);
                buffer.put(decrypted);
            }

            position += size;
        }
    }
}
