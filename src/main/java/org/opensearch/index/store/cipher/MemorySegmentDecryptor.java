/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.cipher;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

@SuppressWarnings("preview")
public class MemorySegmentDecryptor {

    private static final byte[] ZERO_SKIP = new byte[AesCipherFactory.AES_BLOCK_SIZE_BYTES];
    private static final int DEFAULT_MAX_CHUNK_SIZE = 16_384;

    private static final ThreadLocal<Cipher> CIPHER_POOL = ThreadLocal.withInitial(() -> {
        try {
            return Cipher.getInstance("AES/CTR/NoPadding", "SunJCE");
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
    });

    private MemorySegmentDecryptor() {

    }

    public static void decryptInPlace(Arena arena, long addr, long length, byte[] key, byte[] iv, long fileOffset) throws Exception {
        // Get thread-local cipher
        Cipher cipher = CIPHER_POOL.get();
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        byte[] ivCopy = Arrays.copyOf(iv, iv.length);

        int blockOffset = (int) (fileOffset / AesCipherFactory.AES_BLOCK_SIZE_BYTES);

        ivCopy[AesCipherFactory.IV_ARRAY_LENGTH - 1] = (byte) blockOffset;
        ivCopy[AesCipherFactory.IV_ARRAY_LENGTH - 2] = (byte) (blockOffset >>> 8);
        ivCopy[AesCipherFactory.IV_ARRAY_LENGTH - 3] = (byte) (blockOffset >>> 16);
        ivCopy[AesCipherFactory.IV_ARRAY_LENGTH - 4] = (byte) (blockOffset >>> 24);

        cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(ivCopy));

        if (fileOffset % AesCipherFactory.AES_BLOCK_SIZE_BYTES > 0) {
            cipher.update(ZERO_SKIP, 0, (int) (fileOffset % AesCipherFactory.AES_BLOCK_SIZE_BYTES));
        }

        MemorySegment segment = MemorySegment.ofAddress(addr).reinterpret(length, arena, null);
        ByteBuffer buffer = segment.asByteBuffer();

        final int CHUNK_SIZE = Math.min(DEFAULT_MAX_CHUNK_SIZE, (int) length); // typecast is safe.
        byte[] chunk = new byte[CHUNK_SIZE];
        byte[] decryptedChunk = new byte[CHUNK_SIZE];

        int position = 0;
        while (position < buffer.capacity()) {
            int size = Math.min(CHUNK_SIZE, buffer.capacity() - position);

            buffer.position(position);
            buffer.get(chunk, 0, size);

            int decryptedLength = cipher.update(chunk, 0, size, decryptedChunk, 0);
            if (decryptedLength > 0) {
                buffer.position(position);
                buffer.put(decryptedChunk, 0, decryptedLength);
            }

            position += size;
        }

        int finalLength = cipher.doFinal(new byte[0], 0, 0, decryptedChunk, 0);
        if (finalLength > 0) {
            buffer.position(position - finalLength);
            buffer.put(decryptedChunk, 0, finalLength);
        }
    }

    public static void decryptInPlace(long addr, long length, byte[] key, byte[] iv, long fileOffset) throws Exception {
        Cipher cipher = CIPHER_POOL.get();
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        byte[] ivCopy = Arrays.copyOf(iv, iv.length);

        int blockOffset = (int) (fileOffset / AesCipherFactory.AES_BLOCK_SIZE_BYTES);

        ivCopy[AesCipherFactory.IV_ARRAY_LENGTH - 1] = (byte) blockOffset;
        ivCopy[AesCipherFactory.IV_ARRAY_LENGTH - 2] = (byte) (blockOffset >>> 8);
        ivCopy[AesCipherFactory.IV_ARRAY_LENGTH - 3] = (byte) (blockOffset >>> 16);
        ivCopy[AesCipherFactory.IV_ARRAY_LENGTH - 4] = (byte) (blockOffset >>> 24);

        cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(ivCopy));

        if (fileOffset % AesCipherFactory.AES_BLOCK_SIZE_BYTES > 0) {
            cipher.update(ZERO_SKIP, 0, (int) (fileOffset % AesCipherFactory.AES_BLOCK_SIZE_BYTES));
        }

        MemorySegment segment = MemorySegment.ofAddress(addr).reinterpret(length);
        ByteBuffer buffer = segment.asByteBuffer();

        final int CHUNK_SIZE = Math.min(DEFAULT_MAX_CHUNK_SIZE, (int) length); // typecast is safe.
        byte[] chunk = new byte[CHUNK_SIZE];
        byte[] decryptedChunk = new byte[CHUNK_SIZE];

        int position = 0;
        while (position < buffer.capacity()) {
            int size = Math.min(CHUNK_SIZE, buffer.capacity() - position);

            buffer.position(position);
            buffer.get(chunk, 0, size);

            int decryptedLength = cipher.update(chunk, 0, size, decryptedChunk, 0);
            if (decryptedLength > 0) {
                buffer.position(position);
                buffer.put(decryptedChunk, 0, decryptedLength);
            }

            position += size;
        }

        int finalLength = cipher.doFinal(new byte[0], 0, 0, decryptedChunk, 0);
        if (finalLength > 0) {
            buffer.position(position - finalLength);
            buffer.put(decryptedChunk, 0, finalLength);
        }
    }

    public static void decryptSegment(MemorySegment segment, long fileOffset, byte[] key, byte[] iv, int segmentSize) throws Exception {
        Cipher cipher = CIPHER_POOL.get();
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        byte[] ivCopy = Arrays.copyOf(iv, iv.length);

        int blockOffset = (int) (fileOffset / AesCipherFactory.AES_BLOCK_SIZE_BYTES);

        ivCopy[AesCipherFactory.IV_ARRAY_LENGTH - 1] = (byte) blockOffset;
        ivCopy[AesCipherFactory.IV_ARRAY_LENGTH - 2] = (byte) (blockOffset >>> 8);
        ivCopy[AesCipherFactory.IV_ARRAY_LENGTH - 3] = (byte) (blockOffset >>> 16);
        ivCopy[AesCipherFactory.IV_ARRAY_LENGTH - 4] = (byte) (blockOffset >>> 24);

        cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(ivCopy));

        if (fileOffset % AesCipherFactory.AES_BLOCK_SIZE_BYTES > 0) {
            cipher.update(ZERO_SKIP, 0, (int) (fileOffset % AesCipherFactory.AES_BLOCK_SIZE_BYTES));
        }

        ByteBuffer buffer = segment.asByteBuffer();
        final int CHUNK_SIZE = Math.min(DEFAULT_MAX_CHUNK_SIZE, segmentSize);
        byte[] chunk = new byte[CHUNK_SIZE];
        byte[] decryptedChunk = new byte[CHUNK_SIZE];

        int position = 0;
        while (position < buffer.capacity()) {
            int size = Math.min(CHUNK_SIZE, buffer.capacity() - position);

            buffer.position(position);
            buffer.get(chunk, 0, size);

            int decryptedLength = cipher.update(chunk, 0, size, decryptedChunk, 0);
            if (decryptedLength > 0) {
                buffer.position(position);
                buffer.put(decryptedChunk, 0, decryptedLength);
            }

            position += size;
        }

    }
}
