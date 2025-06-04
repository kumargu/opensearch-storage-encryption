/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.mmap;

/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

/*
* Modifications Copyright OpenSearch Contributors. See
* GitHub history for details.
*/
import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Provider;
import java.util.Arrays;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BiPredicate;
import java.util.function.Function;
import java.util.stream.IntStream;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.store.IOContext;
import org.apache.lucene.store.IndexInput;
import org.apache.lucene.store.MMapDirectory;
import org.opensearch.common.SuppressForbidden;
import org.opensearch.index.store.cipher.CipherFactory;
import org.opensearch.index.store.cipher.OpenSslPanamaCipher;
import org.opensearch.index.store.iv.KeyIvResolver;

@SuppressWarnings("preview")
@SuppressForbidden(reason = "temporary bypass")
public final class CryptoMMapDirectoryLargeFiles extends MMapDirectory {

    private static final Logger LOGGER = LogManager.getLogger(CryptoMMapDirectory.class);

    private final KeyIvResolver keyIvResolver;

    private static final Linker LINKER = Linker.nativeLinker();
    public static final int PROT_READ = 0x1;
    private static final int PROT_WRITE = 0x2;
    private static final int MAP_PRIVATE = 0x02;
    private static final MethodHandle MMAP;
    private static final MethodHandle MADVISE;
    public static final MethodHandle MPROTECT;
    private static final MethodHandle GET_PAGE_SIZE;

    private static final int MADV_NORMAL = 0;
    private static final int MADV_POPULATE_WRITE = 23;
    private static final int MADV_WILLNEED = 3;

    private static final SymbolLookup LIBC = loadLibc();

    private Function<String, Optional<String>> groupingFunction = GROUP_BY_SEGMENT;
    private final ConcurrentHashMap<String, RefCountedSharedArena> arenas = new ConcurrentHashMap<>();

    private static final int SHARED_ARENA_PERMITS = checkMaxPermits(getSharedArenaMaxPermitsSysprop());

    private static SymbolLookup loadLibc() {
        String os = System.getProperty("os.name").toLowerCase();
        if (os.contains("mac")) {
            return SymbolLookup.libraryLookup("/usr/lib/libSystem.B.dylib", Arena.global());
        } else if (os.contains("linux")) {
            try {
                // Try the 64-bit version first
                return SymbolLookup.libraryLookup("/lib64/libc.so.6", Arena.global());
            } catch (Exception e) {
                try {
                    // Fall back to the 32-bit version
                    return SymbolLookup.libraryLookup("/lib/libc.so.6", Arena.global());
                } catch (Exception e2) {
                    throw new RuntimeException("Could not load libc from either /lib64/libc.so.6 or /lib/libc.so.6", e2);
                }
            }
        } else {
            throw new UnsupportedOperationException("Unsupported OS: " + os);
        }
    }

    static {
        try {
            // First try to find mmap
            Optional<MemorySegment> mmapSymbol = LIBC.find("mmap");
            if (mmapSymbol.isEmpty()) {
                // If mmap is not found, try mmap64 on some systems
                mmapSymbol = LIBC.find("mmap64");
            }

            if (mmapSymbol.isEmpty()) {
                throw new RuntimeException("Could not find mmap or mmap64 symbol");
            }

            MMAP = LINKER
                .downcallHandle(
                    mmapSymbol.get(),
                    FunctionDescriptor
                        .of(
                            ValueLayout.ADDRESS,
                            ValueLayout.ADDRESS, // addr
                            ValueLayout.JAVA_LONG, // length
                            ValueLayout.JAVA_INT, // prot
                            ValueLayout.JAVA_INT, // flags
                            ValueLayout.JAVA_INT, // fd
                            ValueLayout.JAVA_LONG // offset
                        )
                );

            MADVISE = LINKER
                .downcallHandle(
                    LIBC.find("madvise").orElseThrow(),
                    FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.JAVA_INT)
                );

            MPROTECT = LINKER
                .downcallHandle(
                    LIBC.find("mprotect").orElseThrow(),
                    FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.JAVA_INT)
                );

            GET_PAGE_SIZE = LINKER.downcallHandle(LIBC.find("getpagesize").orElseThrow(), FunctionDescriptor.of(ValueLayout.JAVA_INT));
        } catch (Throwable e) {
            throw new RuntimeException("Failed to load mmap", e);
        }
    }

    public static int getPageSize() {
        try {
            return (int) GET_PAGE_SIZE.invokeExact();
        } catch (Throwable e) {
            return 4096; // fallback to common page size
        }
    }

    public CryptoMMapDirectoryLargeFiles(Path path, Provider provider, KeyIvResolver keyIvResolver) throws IOException {
        super(path);
        this.keyIvResolver = keyIvResolver;
    }

    /**
     * Sets the preload predicate based on file extension list.
     *
     * @param preLoadExtensions extensions to preload (e.g., ["dvd", "tim",
     * "*"])
     * @throws IOException if preload configuration fails
     */
    public void setPreloadExtensions(Set<String> preLoadExtensions) throws IOException {
        if (!preLoadExtensions.isEmpty()) {
            this.setPreload(createPreloadPredicate(preLoadExtensions));
        }
    }

    private static BiPredicate<String, IOContext> createPreloadPredicate(Set<String> preLoadExtensions) {
        if (preLoadExtensions.contains("*")) {
            return MMapDirectory.ALL_FILES;
        }
        return (fileName, context) -> {
            int dotIndex = fileName.lastIndexOf('.');
            if (dotIndex > 0) {
                String ext = fileName.substring(dotIndex + 1);
                return preLoadExtensions.contains(ext);
            }
            return false;
        };
    }

    public static void madvise(long address, long length, int advice) throws Throwable {
        int rc = (int) MADVISE.invokeExact(MemorySegment.ofAddress(address), length, advice);
        if (rc != 0) {
            throw new RuntimeException("madvise failed with rc=" + rc);
        }
    }

    /**
    * Configures a grouping function for files that are part of the same logical group. 
    * The gathering of files into a logical group is a hint that allows for better 
    * handling of resources.
    *
    * <p>By default, grouping is {@link #GROUP_BY_SEGMENT}. To disable, invoke this 
    * method with {@link #NO_GROUPING}.
    *
    * @param groupingFunction a function that accepts a file name and returns an 
    *     optional group key. If the optional is present, then its value is the 
    *     logical group to which the file belongs. Otherwise, the file name is not 
    *     associated with any logical group.
    */
    public void setGroupingFunction(Function<String, Optional<String>> groupingFunction) {
        this.groupingFunction = groupingFunction;
    }

    /**
     * Gets the current grouping function.
     */
    public Function<String, Optional<String>> getGroupingFunction() {
        return this.groupingFunction;
    }

    /**
    * Gets an arena for the given filename, potentially aggregating files from the same segment into
    * a single ref counted shared arena. A ref counted shared arena, if created will be added to the
    * given arenas map.
    */
    private Arena getSharedArena(String name, ConcurrentHashMap<String, RefCountedSharedArena> arenas) {
        final var group = groupingFunction.apply(name);

        if (group.isEmpty()) {
            return Arena.ofShared();
        }

        String key = group.get();
        var refCountedArena = arenas.computeIfAbsent(key, s -> new RefCountedSharedArena(s, () -> arenas.remove(s), SHARED_ARENA_PERMITS));
        if (refCountedArena.acquire()) {
            return refCountedArena;
        } else {
            return arenas.compute(key, (s, v) -> {
                if (v != null && v.acquire()) {
                    return v;
                } else {
                    v = new RefCountedSharedArena(s, () -> arenas.remove(s), SHARED_ARENA_PERMITS);
                    v.acquire(); // guaranteed to succeed
                    return v;
                }
            });
        }
    }

    private static int getSharedArenaMaxPermitsSysprop() {
        int ret = 1024; // default value
        try {
            String str = System.getProperty(SHARED_ARENA_MAX_PERMITS_SYSPROP);
            if (str != null) {
                ret = Integer.parseInt(str);
            }
        } catch (@SuppressWarnings("unused") NumberFormatException | SecurityException ignored) {
            LOGGER.warn("Cannot read sysprop " + SHARED_ARENA_MAX_PERMITS_SYSPROP + ", so the default value will be used.");
        }
        return ret;
    }

    private static int checkMaxPermits(int maxPermits) {
        if (RefCountedSharedArena.validMaxPermits(maxPermits)) {
            return maxPermits;
        }
        LOGGER
            .warn(
                "Invalid value for sysprop "
                    + MMapDirectory.SHARED_ARENA_MAX_PERMITS_SYSPROP
                    + ", must be positive and <= 0x07FF. The default value will be used."
            );
        return RefCountedSharedArena.DEFAULT_MAX_PERMITS;
    }

    @Override
    public IndexInput openInput(String name, IOContext context) throws IOException {
        ensureOpen();
        ensureCanRead(name);

        Path file = getDirectory().resolve(name);
        long size = Files.size(file);

        boolean confined = context == IOContext.READONCE;
        Arena arena = confined ? Arena.ofConfined() : Arena.ofShared();

        int chunkSizePower = 34;

        try {
            // Open the file using native open() call
            int fd = openFile(file.toString());
            if (fd == -1) {
                throw new IOException("Failed to open file: " + file);
            }

            try {
                MemorySegment[] segments = mmapAndDecrypt(file, fd, size, arena, chunkSizePower, name, context);
                return MemorySegmentIndexInput
                    .newInstance("CryptoMemorySegmentIndexInput(path=\"" + file + "\")", arena, segments, size, chunkSizePower);
            } finally {
                // Close the file descriptor
                closeFile(fd);
            }

        } catch (Throwable t) {
            arena.close();
            throw new IOException("Failed to mmap/decrypt " + file, t);
        }
    }

    private MemorySegment[] mmapAndDecrypt(Path path, int fd, long size, Arena arena, int chunkSizePower, String name, IOContext context)
        throws Throwable {
        final long chunkSize = 1L << chunkSizePower;
        final int numSegments = (int) ((size + chunkSize - 1) >>> chunkSizePower);
        MemorySegment[] segments = new MemorySegment[numSegments];

        // Get madvise flags once - they don't change per segment
        boolean shouldPreload = LuceneIOContextMAdvise.shouldPreload(name, size);
        int madviseFlags = LuceneIOContextMAdvise.getMAdviseFlags(context, name);

        long offset = 0;
        for (int i = 0; i < numSegments; i++) {
            long remaining = size - offset;
            long segmentSize = Math.min(chunkSize, remaining);

            MemorySegment mmapSegment = (MemorySegment) MMAP
                .invoke(MemorySegment.NULL, segmentSize, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, offset);
            if (mmapSegment.address() == 0 || mmapSegment.address() == -1) {
                throw new IOException("mmap failed at offset: " + offset);
            }

            // if (segmentSize <= (4L << 20)) { // Small segment - try to populate
            // if (mmapSegment.address() % getPageSize() == 0) {
            // try {
            // madvise(mmapSegment.address(), segmentSize, MADV_POPULATE_WRITE);
            // } catch (Throwable t) {
            // LOGGER.warn("MADV_POPULATE_WRITE failed for {}: {}", name, t.getMessage());
            // }
            // } else {
            // LOGGER.warn("Skipping POPULATE_WRITE for {} - address not page aligned", name);
            // // Could still do touchPages here if critical
            // }
            // } else if (madviseFlags != MADV_NORMAL && mmapSegment.address() % getPageSize() == 0) {
            // try {
            // madvise(mmapSegment.address(), segmentSize, madviseFlags);
            // } catch (Throwable t) {
            // LOGGER.warn("madvise failed for {} at context {} advise: {}", name, context, madviseFlags, t);
            // }
            // }

            try {
                if (mmapSegment.address() % getPageSize() == 0) {
                    madvise(mmapSegment.address(), segmentSize, MADV_WILLNEED);
                }
            } catch (Throwable t) {
                LOGGER.warn("madvise failed for {} at context {} advise: {}", name, context, madviseFlags, t);
            }

            MemorySegment segment = MemorySegment.ofAddress(mmapSegment.address()).reinterpret(segmentSize, arena, null);

            decryptSegmentInPlaceParallel(arena, segment, offset);

            segments[i] = segment;
            offset += segmentSize;
        }

        return segments;
    }

    // private void decryptSegment(MemorySegment segment, long offset) throws Exception {
    // final byte[] key = this.keyIvResolver.getDataKey().getEncoded();
    // final byte[] baseIv = this.keyIvResolver.getIvBytes();

    // Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
    // SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
    // byte[] ivCopy = Arrays.copyOf(baseIv, baseIv.length);

    // int blockOffset = (int) (offset / CipherFactory.AES_BLOCK_SIZE_BYTES);
    // for (int i = CipherFactory.IV_ARRAY_LENGTH - 1; i >= CipherFactory.IV_ARRAY_LENGTH - CipherFactory.COUNTER_SIZE_BYTES; i--) {
    // ivCopy[i] = (byte) blockOffset;
    // blockOffset >>>= Byte.SIZE;
    // }

    // cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(ivCopy));

    // // Process the data in smaller chunks to avoid OOM
    // ByteBuffer buffer = segment.asByteBuffer();
    // final int CHUNK_SIZE = 16_384; // 8KB chunks
    // byte[] chunk = new byte[CHUNK_SIZE];

    // int position = 0;
    // while (position < buffer.capacity()) {
    // int size = Math.min(CHUNK_SIZE, buffer.capacity() - position);
    // buffer.position(position);
    // buffer.get(chunk, 0, size);

    // byte[] decrypted;
    // if (position + size >= buffer.capacity()) {
    // // Last chunk
    // decrypted = cipher.doFinal(chunk, 0, size);
    // } else {
    // decrypted = cipher.update(chunk, 0, size);
    // }

    // if (decrypted != null) {
    // buffer.position(position);
    // buffer.put(decrypted);
    // }

    // position += size;
    // }
    // }

    private void decryptSegment(MemorySegment segment, long offset) throws Exception {
        final byte[] key = this.keyIvResolver.getDataKey().getEncoded();
        final byte[] baseIv = this.keyIvResolver.getIvBytes();

        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        byte[] ivCopy = Arrays.copyOf(baseIv, baseIv.length);

        int blockOffset = (int) (offset / CipherFactory.AES_BLOCK_SIZE_BYTES);
        for (int i = CipherFactory.IV_ARRAY_LENGTH - 1; i >= CipherFactory.IV_ARRAY_LENGTH - CipherFactory.COUNTER_SIZE_BYTES; i--) {
            ivCopy[i] = (byte) blockOffset;
            blockOffset >>>= Byte.SIZE;
        }

        cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(ivCopy));

        // Process the data in smaller chunks to avoid OOM
        ByteBuffer buffer = segment.asByteBuffer();

        final int CHUNK_SIZE = (segment.byteSize() <= (1 << 20)) ? 8_192 : 32_768;

        byte[] chunk = new byte[CHUNK_SIZE];

        long startTime = System.nanoTime();

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

        final long size = segment.byteSize();

        long endTime = System.nanoTime();
        long elapsedMs = (endTime - startTime) / 1_000_000;

        // // Optional logging
        // LOGGER.info(" SunJCE decryption of {} MiB took {} ms", size / 1048576.0, elapsedMs);
    }

    public void decryptSegmentInPlaceParallel(Arena arena, MemorySegment segment, long segmentOffsetInFile) throws Throwable {
        final long size = segment.byteSize();

        final int oneMB = 1 << 20; // 1 MiB
        final int twoMB = 1 << 21; // 2 MiB
        final int fourMB = 1 << 22; // 4 MiB
        final int eightMB = 1 << 23; // 8 MiB
        final int sixteenMB = 1 << 24; // 16 MiB

        final byte[] key = this.keyIvResolver.getDataKey().getEncoded();
        final byte[] iv = this.keyIvResolver.getIvBytes();

        // Fast-path: no parallelism for ≤ 2 MiB
        if (size <= (4L << 20)) {
            long start = System.nanoTime();

            // OpenSslPanamaCipher.decryptInPlaceV2(arena, segment.address(), size, key, iv, segmentOffsetInFile);

            decryptSegment(segment, segmentOffsetInFile);

            long end = System.nanoTime();
            long durationMs = (end - start) / 1_000_000;
            // Optional logging
            // LOGGER.info("Fast-path decryption of {} MiB at offset {} took {} ms", size / 1048576.0, segmentOffsetInFile, durationMs);

            return;
        }

        // Choose adaptive chunk size
        final int chunkSize;
        if (size <= (8L << 20)) {
            chunkSize = twoMB;
        } else if (size <= (16L << 20)) {
            chunkSize = fourMB;
        } else if (size <= (32L << 20)) {
            chunkSize = fourMB;
        } else if (size <= (64L << 20)) {
            chunkSize = eightMB;
        } else {
            chunkSize = sixteenMB;
        }

        final int numChunks = (int) ((size + chunkSize - 1) / chunkSize);
        long startTime = System.nanoTime();

        IntStream.range(0, numChunks).parallel().forEach(i -> {
            long offset = (long) i * chunkSize;
            long length = Math.min(chunkSize, size - offset);
            long fileOffset = segmentOffsetInFile + offset;
            long addr = segment.address() + offset;

            try {
                OpenSslPanamaCipher.decryptInPlace(addr, length, key, iv, fileOffset);
            } catch (Throwable t) {
                throw new RuntimeException("Decryption failed at offset: " + fileOffset, t);
            }
        });

        long endTime = System.nanoTime();
        long elapsedMs = (endTime - startTime) / 1_000_000;

        // Optional logging
        // LOGGER
        // .info(
        // "Parallel decryption of {} chunks ({} MiB total) at offset {} took {} ms",
        // numChunks,
        // String.format("%.2f", size / 1048576.0),
        // segmentOffsetInFile,
        // elapsedMs
        // );
    }

    private static final MethodHandle OPEN;
    private static final MethodHandle CLOSE;

    static {
        try {
            OPEN = LINKER
                .downcallHandle(
                    LIBC.find("open").orElseThrow(),
                    FunctionDescriptor
                        .of(
                            ValueLayout.JAVA_INT,
                            ValueLayout.ADDRESS, // const char *pathname
                            ValueLayout.JAVA_INT // int flags
                        )
                );

            CLOSE = LINKER
                .downcallHandle(
                    LIBC.find("close").orElseThrow(),
                    FunctionDescriptor
                        .of(
                            ValueLayout.JAVA_INT,
                            ValueLayout.JAVA_INT // int fd
                        )
                );
        } catch (Throwable e) {
            throw new RuntimeException("Failed to bind open/close", e);
        }
    }

    private static int openFile(String path) throws Throwable {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment pathSegment = arena.allocateUtf8String(path);
            return (int) OPEN.invoke(pathSegment, 0); // O_RDONLY = 0
        }
    }

    private static void closeFile(int fd) throws Throwable {
        CLOSE.invoke(fd);
    }
}
