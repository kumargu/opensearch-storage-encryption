/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.mmap;

import java.io.EOFException;
import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.store.AlreadyClosedException;
import org.apache.lucene.store.IndexInput;
import org.apache.lucene.store.RandomAccessInput;
import org.apache.lucene.util.ArrayUtil;
import static org.opensearch.index.store.cipher.OpenSslPanamaCipher.decryptInPlaceV2;
import org.opensearch.index.store.iv.KeyIvResolver;
import static org.opensearch.index.store.mmap.CryptoMMapDirectory.getPageSize;

@SuppressWarnings("preview")
public class MemorySegmentIndexInput extends IndexInput implements RandomAccessInput {

    private static final Logger LOGGER = LogManager.getLogger(MemorySegmentIndexInput.class);

    static final ValueLayout.OfByte LAYOUT_BYTE = ValueLayout.JAVA_BYTE;
    static final ValueLayout.OfShort LAYOUT_LE_SHORT = ValueLayout.JAVA_SHORT_UNALIGNED.withOrder(ByteOrder.LITTLE_ENDIAN);
    static final ValueLayout.OfInt LAYOUT_LE_INT = ValueLayout.JAVA_INT_UNALIGNED.withOrder(ByteOrder.LITTLE_ENDIAN);
    static final ValueLayout.OfLong LAYOUT_LE_LONG = ValueLayout.JAVA_LONG_UNALIGNED.withOrder(ByteOrder.LITTLE_ENDIAN);
    static final ValueLayout.OfFloat LAYOUT_LE_FLOAT = ValueLayout.JAVA_FLOAT_UNALIGNED.withOrder(ByteOrder.LITTLE_ENDIAN);

    final long length;
    final long chunkSizeMask;
    final int chunkSizePower;
    final Arena arena;
    final MemorySegment[] segments;
    final KeyIvResolver keyIvResolver;
    final ConcurrentHashMap<Long, Boolean> decryptedPages;

    int curSegmentIndex = -1;
    MemorySegment curSegment; // redundant for speed: segments[curSegmentIndex], also marker if closed!
    long curPosition; // relative to curSegment, not globally

    public static MemorySegmentIndexInput newInstance(
        String resourceDescription,
        Arena arena,
        MemorySegment[] segments,
        long length,
        int chunkSizePower,
        KeyIvResolver keyIvResolver
    ) {
        ConcurrentHashMap<Long, Boolean> decryptedPages = new ConcurrentHashMap<>();

        assert Arrays.stream(segments).map(MemorySegment::scope).allMatch(arena.scope()::equals);

        if (segments.length == 1) {
            return new SingleSegmentImpl(resourceDescription, arena, segments[0], length, chunkSizePower, keyIvResolver, decryptedPages);
        } else {
            return new MultiSegmentImpl(resourceDescription, arena, segments, 0, length, chunkSizePower, keyIvResolver, decryptedPages);
        }

    }

    private MemorySegmentIndexInput(
        String resourceDescription,
        Arena arena,
        MemorySegment[] segments,
        long length,
        int chunkSizePower,
        KeyIvResolver keyIvResolver,
        ConcurrentHashMap<Long, Boolean> decryptedPages
    ) {
        super(resourceDescription);
        this.arena = arena;
        this.segments = segments;
        this.length = length;
        this.chunkSizePower = chunkSizePower;
        this.chunkSizeMask = (1L << chunkSizePower) - 1L;
        this.curSegment = segments[0];
        this.keyIvResolver = keyIvResolver;
        this.decryptedPages = decryptedPages;
    }

    void ensureOpen() {
        if (curSegment == null) {
            throw alreadyClosed(null);
        }
    }

    private synchronized static void decryptAndProtect(
        ConcurrentHashMap<Long, Boolean> decryptedPages,
        long addr,
        long length,
        long fileOffset,
        byte[] key,
        byte[] iv
    ) throws IOException {
        int pageSize = getPageSize();
        long alignedAddr = addr & ~(pageSize - 1);
        long requestEnd = addr + length;
        long alignedEnd = ((requestEnd + pageSize - 1) & ~(pageSize - 1));

        // Calculate the base file offset for the aligned memory start
        long baseFileOffset = fileOffset - (addr - alignedAddr);

        for (long pageAddr = alignedAddr; pageAddr < alignedEnd; pageAddr += pageSize) {
            // Calculate file offset for this specific page
            long pageFileOffset = baseFileOffset + (pageAddr - alignedAddr);

            // Use PAGE-ALIGNED FILE POSITION as key instead of memory address
            long pageFileKey = pageFileOffset & ~(pageSize - 1);
            Long pageKey = pageFileKey;

            // Try to "claim" this page for decryption
            // Returns null if we successfully claimed it (page wasn't decrypted)
            // Returns Boolean.TRUE if someone else already decrypted it
            if (decryptedPages.putIfAbsent(pageKey, Boolean.TRUE) != null) {
                LOGGER.info("Found page being decrypted page {} ", pageKey);
                // Someone else already decrypted this page, skip it
                continue;
            }

            // We successfully claimed this page, now decrypt it

            try (Arena localArena = Arena.ofConfined()) {
                try {
                    decryptInPlaceV2(localArena, pageAddr, pageSize, key, iv, pageFileOffset);
                    LOGGER.info("Successfully decrypted page {}", pageKey);
                } catch (Exception e) {
                    decryptedPages.remove(pageKey);
                    throw new IOException("Decryption failed for page at " + pageAddr, e);
                } catch (Throwable e) {
                    decryptedPages.remove(pageKey);
                    throw new IOException("Decryption failed for page at " + pageAddr, e);
                }
            }
        }
    }

    // the unused parameter is just to silence javac about unused variables
    RuntimeException handlePositionalIOOBE(RuntimeException unused, String action, long pos) throws IOException {
        if (pos < 0L) {
            return new IllegalArgumentException(action + " negative position (pos=" + pos + "): " + this);
        } else {
            throw new EOFException(action + " past EOF (pos=" + pos + "): " + this);
        }
    }

    // the unused parameter is just to silence javac about unused variables
    AlreadyClosedException alreadyClosed(RuntimeException unused) {
        return new AlreadyClosedException("Already closed: " + this);
    }

    @Override
    public final byte readByte() throws IOException {
        try {
            // Decrypt current byte before reading
            long addr = curSegment.address() + curPosition;
            long fileOffset = getFilePointer();

            decryptAndProtect(
                this.decryptedPages,
                addr,
                1,
                fileOffset,
                keyIvResolver.getDataKey().getEncoded(),
                keyIvResolver.getIvBytes()
            );

            final byte v = curSegment.get(LAYOUT_BYTE, curPosition);
            curPosition++;
            return v;
        } catch (@SuppressWarnings("unused") IndexOutOfBoundsException e) {
            try {
                do {
                    curSegmentIndex++;
                    if (curSegmentIndex >= segments.length) {
                        throw new EOFException("read past EOF: " + this);
                    }
                    curSegment = segments[curSegmentIndex];
                    curPosition = 0L;
                } while (curSegment.byteSize() == 0L);

                // Decrypt the byte in the new segment
                long addr = curSegment.address() + curPosition;
                long fileOffset = getFilePointer();

                decryptAndProtect(
                    this.decryptedPages,
                    addr,
                    1,
                    fileOffset,
                    keyIvResolver.getDataKey().getEncoded(),
                    keyIvResolver.getIvBytes()
                );

                final byte v = curSegment.get(LAYOUT_BYTE, curPosition);
                curPosition++;
                return v;
            } catch (NullPointerException | IllegalStateException e2) {
                throw alreadyClosed(e2);
            } catch (IOException e2) {
                throw new IOException("Decryption failed", e2);
            }
        } catch (NullPointerException | IllegalStateException e) {
            throw alreadyClosed(e);
        } catch (IOException e) {
            throw new IOException("Decryption failed", e);
        }
    }

    @Override
    public final void readBytes(byte[] b, int offset, int len) throws IOException {
        try {
            long addr = curSegment.address() + curPosition;
            long fileOffset = getFilePointer();

            // Decrypt the entire region we're about to read
            decryptAndProtect(
                this.decryptedPages,
                addr,
                len,
                fileOffset,
                keyIvResolver.getDataKey().getEncoded(),
                keyIvResolver.getIvBytes()
            );

            MemorySegment.copy(curSegment, LAYOUT_BYTE, curPosition, b, offset, len);
            curPosition += len;
        } catch (IndexOutOfBoundsException e) {
            readBytesBoundary(b, offset, len);
        } catch (NullPointerException | IllegalStateException e) {
            throw alreadyClosed(e);
        } catch (IOException e) {
            throw new IOException("Decryption or read failed", e);
        }
    }

    private void readBytesBoundary(byte[] b, int offset, int len) throws IOException {
        long startFileOffset = getFilePointer(); // Capture once at start
        int originalLen = len;
        try {
            long curAvail = curSegment.byteSize() - curPosition;
            while (len > curAvail) {
                long addr = curSegment.address() + curPosition;
                long fileOffset = startFileOffset + (originalLen - len); // Calculate relative offset
                decryptAndProtect(
                    this.decryptedPages,
                    addr,
                    curAvail,
                    fileOffset,
                    keyIvResolver.getDataKey().getEncoded(),
                    keyIvResolver.getIvBytes()
                );
                MemorySegment.copy(curSegment, LAYOUT_BYTE, curPosition, b, offset, (int) curAvail);
                len -= curAvail;
                offset += curAvail;
                curSegmentIndex++;
                if (curSegmentIndex >= segments.length) {
                    throw new EOFException("read past EOF: " + this);
                }
                curSegment = segments[curSegmentIndex];
                curPosition = 0L;
                curAvail = curSegment.byteSize();
            }

            long addr = curSegment.address() + curPosition;
            long fileOffset = startFileOffset + (originalLen - len);
            decryptAndProtect(
                this.decryptedPages,
                addr,
                len,
                fileOffset,
                keyIvResolver.getDataKey().getEncoded(),
                keyIvResolver.getIvBytes()
            );
            MemorySegment.copy(curSegment, LAYOUT_BYTE, curPosition, b, offset, len);
            curPosition += len;
        } catch (NullPointerException | IllegalStateException e) {
            throw alreadyClosed(e);
        } catch (IOException e) {
            throw new IOException("Decryption failed", e);
        }
    }

    /**
     * Helper method to decrypt current segment remainder and next segment for
     * boundary crossing reads
     */
    private void decryptForBoundaryCrossing() throws IOException {
        // Decrypt remainder of current segment
        long currentSegmentRemaining = curSegment.byteSize() - curPosition;
        if (currentSegmentRemaining > 0) {
            long addr = curSegment.address() + curPosition;
            long fileOffset = getFilePointer();
            decryptAndProtect(
                this.decryptedPages,
                addr,
                currentSegmentRemaining,
                fileOffset,
                keyIvResolver.getDataKey().getEncoded(),
                keyIvResolver.getIvBytes()
            );
        }

        // Decrypt entire next segment if it exists
        if (curSegmentIndex + 1 < segments.length) {
            MemorySegment nextSegment = segments[curSegmentIndex + 1];
            long addr = nextSegment.address();
            long fileOffset = (long) (curSegmentIndex + 1) << chunkSizePower;
            decryptAndProtect(
                this.decryptedPages,
                addr,
                nextSegment.byteSize(),
                fileOffset,
                keyIvResolver.getDataKey().getEncoded(),
                keyIvResolver.getIvBytes()
            );
        }
    }

    @Override
    public void readInts(int[] dst, int offset, int length) throws IOException {
        try {
            // Decrypt the range we're about to read
            long totalBytes = Integer.BYTES * (long) length;
            long addr = curSegment.address() + curPosition;
            long fileOffset = getFilePointer();

            decryptAndProtect(
                this.decryptedPages,
                addr,
                totalBytes,
                fileOffset,
                keyIvResolver.getDataKey().getEncoded(),
                keyIvResolver.getIvBytes()
            );

            MemorySegment.copy(curSegment, LAYOUT_LE_INT, curPosition, dst, offset, length);
            curPosition += totalBytes;
        } catch (@SuppressWarnings("unused") IndexOutOfBoundsException iobe) {
            // Crossing segment boundaries - decrypt current segment remainder and next segment
            // Decrypt remainder of current segment
            decryptForBoundaryCrossing();
            super.readInts(dst, offset, length);
        } catch (NullPointerException | IllegalStateException e) {
            throw alreadyClosed(e);
        }
    }

    @Override
    public void readLongs(long[] dst, int offset, int length) throws IOException {
        try {
            // Decrypt the range we're about to read
            long totalBytes = Long.BYTES * (long) length;
            long addr = curSegment.address() + curPosition;
            long fileOffset = getFilePointer();

            decryptAndProtect(
                this.decryptedPages,
                addr,
                totalBytes,
                fileOffset,
                keyIvResolver.getDataKey().getEncoded(),
                keyIvResolver.getIvBytes()
            );

            MemorySegment.copy(curSegment, LAYOUT_LE_LONG, curPosition, dst, offset, length);
            curPosition += totalBytes;
        } catch (@SuppressWarnings("unused") IndexOutOfBoundsException iobe) {
            // Crossing segment boundaries - decrypt segments then delegate to super
            decryptForBoundaryCrossing();
            super.readLongs(dst, offset, length);
        } catch (NullPointerException | IllegalStateException e) {
            throw alreadyClosed(e);
        }
    }

    @Override
    public void readFloats(float[] dst, int offset, int length) throws IOException {
        try {
            // Decrypt the range we're about to read
            long totalBytes = Float.BYTES * (long) length;
            long addr = curSegment.address() + curPosition;
            long fileOffset = getFilePointer();

            decryptAndProtect(
                this.decryptedPages,
                addr,
                totalBytes,
                fileOffset,
                keyIvResolver.getDataKey().getEncoded(),
                keyIvResolver.getIvBytes()
            );

            MemorySegment.copy(curSegment, LAYOUT_LE_FLOAT, curPosition, dst, offset, length);
            curPosition += totalBytes;
        } catch (@SuppressWarnings("unused") IndexOutOfBoundsException iobe) {
            // Crossing segment boundaries - decrypt segments then delegate to super
            decryptForBoundaryCrossing();
            super.readFloats(dst, offset, length);
        } catch (NullPointerException | IllegalStateException e) {
            throw alreadyClosed(e);
        }
    }

    @Override
    public final short readShort() throws IOException {
        try {
            // Decrypt the range we're about to read
            long addr = curSegment.address() + curPosition;
            long fileOffset = getFilePointer();

            decryptAndProtect(
                this.decryptedPages,
                addr,
                Short.BYTES,
                fileOffset,
                keyIvResolver.getDataKey().getEncoded(),
                keyIvResolver.getIvBytes()
            );

            final short v = curSegment.get(LAYOUT_LE_SHORT, curPosition);
            curPosition += Short.BYTES;
            return v;
        } catch (@SuppressWarnings("unused") IndexOutOfBoundsException e) {
            return super.readShort();
        } catch (NullPointerException | IllegalStateException e) {
            throw alreadyClosed(e);
        }
    }

    @Override
    public final int readInt() throws IOException {
        try {
            // Decrypt the range we're about to read
            long addr = curSegment.address() + curPosition;
            long fileOffset = getFilePointer();

            decryptAndProtect(
                this.decryptedPages,
                addr,
                Integer.BYTES,
                fileOffset,
                keyIvResolver.getDataKey().getEncoded(),
                keyIvResolver.getIvBytes()
            );

            final int v = curSegment.get(LAYOUT_LE_INT, curPosition);
            curPosition += Integer.BYTES;
            return v;
        } catch (@SuppressWarnings("unused") IndexOutOfBoundsException e) {
            return super.readInt();
        } catch (NullPointerException | IllegalStateException e) {
            throw alreadyClosed(e);
        }
    }

    @Override
    public final long readLong() throws IOException {
        try {
            // Decrypt the range we're about to read
            long addr = curSegment.address() + curPosition;
            long fileOffset = getFilePointer();

            decryptAndProtect(
                this.decryptedPages,
                addr,
                Long.BYTES,
                fileOffset,
                keyIvResolver.getDataKey().getEncoded(),
                keyIvResolver.getIvBytes()
            );

            final long v = curSegment.get(LAYOUT_LE_LONG, curPosition);
            curPosition += Long.BYTES;
            return v;
        } catch (@SuppressWarnings("unused") IndexOutOfBoundsException e) {
            return super.readLong();
        } catch (NullPointerException | IllegalStateException e) {
            throw alreadyClosed(e);
        }
    }

    @Override
    public long getFilePointer() {
        ensureOpen();
        return (((long) curSegmentIndex) << chunkSizePower) + curPosition;
    }

    @Override
    public void seek(long pos) throws IOException {
        ensureOpen();
        // we use >> here to preserve negative, so we will catch AIOOBE,
        // in case pos + offset overflows.
        final int si = (int) (pos >> chunkSizePower);
        try {
            if (si != curSegmentIndex) {
                final MemorySegment seg = segments[si];
                // write values, on exception all is unchanged
                this.curSegmentIndex = si;
                this.curSegment = seg;
            }
            this.curPosition = Objects.checkIndex(pos & chunkSizeMask, curSegment.byteSize() + 1);
        } catch (IndexOutOfBoundsException e) {
            throw handlePositionalIOOBE(e, "seek", pos);
        }
    }

    @Override
    public byte readByte(long pos) throws IOException {
        try {
            final int si = (int) (pos >> chunkSizePower);
            final long segmentOffset = pos & chunkSizeMask;

            // Calculate address and decrypt the single byte
            long addr = segments[si].address() + segmentOffset;
            long fileOffset = pos; // pos is already the absolute file position
            decryptAndProtect(
                this.decryptedPages,
                addr,
                1,
                fileOffset,
                keyIvResolver.getDataKey().getEncoded(),
                keyIvResolver.getIvBytes()
            );

            return segments[si].get(LAYOUT_BYTE, segmentOffset);
        } catch (IndexOutOfBoundsException ioobe) {
            throw handlePositionalIOOBE(ioobe, "read", pos);
        } catch (NullPointerException | IllegalStateException e) {
            throw alreadyClosed(e);
        }
    }

    // used only by random access methods to handle reads across boundaries
    private void setPos(long pos, int si) throws IOException {
        try {
            final MemorySegment seg = segments[si];
            // write values, on exception above all is unchanged
            this.curPosition = pos & chunkSizeMask;
            this.curSegmentIndex = si;
            this.curSegment = seg;
        } catch (IndexOutOfBoundsException ioobe) {
            throw handlePositionalIOOBE(ioobe, "read", pos);
        } catch (NullPointerException | IllegalStateException e) {
            throw alreadyClosed(e);
        }
    }

    @Override
    public short readShort(long pos) throws IOException {

        final int si = (int) (pos >> chunkSizePower);
        final long segmentOffset = pos & chunkSizeMask;

        try {
            // Calculate address and decrypt the 2 bytes for short
            long addr = segments[si].address() + segmentOffset;
            long fileOffset = pos; // pos is already the absolute file position
            decryptAndProtect(
                this.decryptedPages,
                addr,
                2,
                fileOffset,
                keyIvResolver.getDataKey().getEncoded(),
                keyIvResolver.getIvBytes()
            );

            return segments[si].get(LAYOUT_LE_SHORT, segmentOffset);
        } catch (@SuppressWarnings("unused") IndexOutOfBoundsException ioobe) {
            // either it's a boundary, or read past EOF, fall back:
            setPos(pos, si);
            return readShort();
        } catch (NullPointerException | IllegalStateException e) {
            throw alreadyClosed(e);
        }

    }

    @Override
    public int readInt(long pos) throws IOException {
        final int si = (int) (pos >> chunkSizePower);
        final long segmentOffset = pos & chunkSizeMask;

        try {
            // Add decryption before reading
            long addr = segments[si].address() + segmentOffset;
            long fileOffset = pos; // pos is already the absolute file position

            decryptAndProtect(
                this.decryptedPages,
                addr,
                Integer.BYTES,
                fileOffset,
                keyIvResolver.getDataKey().getEncoded(),
                keyIvResolver.getIvBytes()
            );

            return segments[si].get(LAYOUT_LE_INT, segmentOffset);
        } catch (@SuppressWarnings("unused") IndexOutOfBoundsException ioobe) {
            // either it's a boundary, or read past EOF, fall back:
            setPos(pos, si);
            return readInt();
        } catch (NullPointerException | IllegalStateException e) {
            throw alreadyClosed(e);
        } catch (IOException e) {
            throw new IOException("Decryption failed", e);
        }
    }

    @Override
    public long readLong(long pos) throws IOException {
        final int si = (int) (pos >> chunkSizePower);
        final long segmentOffset = pos & chunkSizeMask;

        try {
            // Add decryption before reading
            long addr = segments[si].address() + segmentOffset;
            long fileOffset = pos; // pos is already the absolute file position

            decryptAndProtect(
                this.decryptedPages,
                addr,
                Long.BYTES,
                fileOffset,
                keyIvResolver.getDataKey().getEncoded(),
                keyIvResolver.getIvBytes()
            );

            return segments[si].get(LAYOUT_LE_LONG, segmentOffset);
        } catch (@SuppressWarnings("unused") IndexOutOfBoundsException ioobe) {
            // either it's a boundary, or read past EOF, fall back:
            setPos(pos, si);
            return readLong();
        } catch (NullPointerException | IllegalStateException e) {
            throw alreadyClosed(e);
        } catch (IOException e) {
            throw new IOException("Decryption failed", e);
        }
    }

    @Override
    public final long length() {
        return length;
    }

    @Override
    public final MemorySegmentIndexInput clone() {
        final MemorySegmentIndexInput clone = buildSlice((String) null, 0L, this.length);
        try {
            clone.seek(getFilePointer());
        } catch (IOException ioe) {
            throw new AssertionError(ioe);
        }

        return clone;
    }

    /**
     * Creates a slice of this index input, with the given description, offset,
     * and length. The slice is seeked to the beginning.
     */
    @Override
    public final MemorySegmentIndexInput slice(String sliceDescription, long offset, long length) {
        if (offset < 0 || length < 0 || offset + length > this.length) {
            throw new IllegalArgumentException(
                "slice() "
                    + sliceDescription
                    + " out of bounds: offset="
                    + offset
                    + ",length="
                    + length
                    + ",fileLength="
                    + this.length
                    + ": "
                    + this
            );
        }

        return buildSlice(sliceDescription, offset, length);
    }

    /**
     * Builds the actual sliced IndexInput (may apply extra offset in
     * subclasses). *
     */
    MemorySegmentIndexInput buildSlice(String sliceDescription, long offset, long length) {
        LOGGER.info("==== Perforiming a slicing =======");

        ensureOpen();

        final long sliceEnd = offset + length;
        final int startIndex = (int) (offset >>> chunkSizePower);
        final int endIndex = (int) (sliceEnd >>> chunkSizePower);

        // we always allocate one more slice, the last one may be a 0 byte one after truncating with
        // asSlice():
        final MemorySegment slices[] = ArrayUtil.copyOfSubArray(segments, startIndex, endIndex + 1);

        // set the last segment's limit for the sliced view.
        slices[slices.length - 1] = slices[slices.length - 1].asSlice(0L, sliceEnd & chunkSizeMask);

        offset = offset & chunkSizeMask;

        final String newResourceDescription = getFullSliceDescription(sliceDescription);
        if (slices.length == 1) {
            return new SingleSegmentImpl(
                newResourceDescription,
                null, // clones don't have an Arena, as they can't close)
                slices[0].asSlice(offset, length),
                length,
                chunkSizePower,
                keyIvResolver,
                this.decryptedPages
            );
        } else {
            return new MultiSegmentImpl(
                newResourceDescription,
                null, // clones don't have an Arena, as they can't close)
                slices,
                offset,
                length,
                chunkSizePower,
                keyIvResolver,
                this.decryptedPages
            );
        }
    }

    @Override
    public final void close() throws IOException {
        if (curSegment == null) {
            return;
        }

        // the master IndexInput has an Arena and is able
        // to release all resources (unmap segments) - a
        // side effect is that other threads still using clones
        // will throw IllegalStateException
        if (arena != null) {
            while (arena.scope().isAlive()) {
                try {
                    arena.close();
                    break;
                } catch (@SuppressWarnings("unused") IllegalStateException e) {
                    Thread.onSpinWait();
                }
            }
        }

        // make sure all accesses to this IndexInput instance throw NPE:
        curSegment = null;
        Arrays.fill(segments, null);
    }

    /**
     * Optimization of MemorySegmentIndexInput for when there is only one
     * segment.
     */
    static final class SingleSegmentImpl extends MemorySegmentIndexInput {

        SingleSegmentImpl(
            String resourceDescription,
            Arena arena,
            MemorySegment segment,
            long length,
            int chunkSizePower,
            KeyIvResolver keyIvResolver,
            ConcurrentHashMap<Long, Boolean> decryptedPages
        ) {
            super(resourceDescription, arena, new MemorySegment[] { segment }, length, chunkSizePower, keyIvResolver, decryptedPages);
            this.curSegmentIndex = 0;
        }

        @Override
        public void seek(long pos) throws IOException {
            ensureOpen();
            try {
                curPosition = Objects.checkIndex(pos, length + 1);
            } catch (IndexOutOfBoundsException e) {
                throw handlePositionalIOOBE(e, "seek", pos);
            }
        }

        @Override
        public long getFilePointer() {
            ensureOpen();
            return curPosition;
        }

        @Override
        public byte readByte(long pos) throws IOException {
            try {
                // For single segment, pos is the absolute file position
                long addr = curSegment.address() + pos;
                decryptAndProtect(decryptedPages, addr, 1, pos, keyIvResolver.getDataKey().getEncoded(), keyIvResolver.getIvBytes());

                return curSegment.get(LAYOUT_BYTE, pos);
            } catch (IndexOutOfBoundsException e) {
                throw handlePositionalIOOBE(e, "read", pos);
            } catch (NullPointerException | IllegalStateException e) {
                throw alreadyClosed(e);
            }
        }

        @Override
        public short readShort(long pos) throws IOException {
            try {
                // Decrypt 2 bytes for short
                long addr = curSegment.address() + pos;
                decryptAndProtect(decryptedPages, addr, 2, pos, keyIvResolver.getDataKey().getEncoded(), keyIvResolver.getIvBytes());

                return curSegment.get(LAYOUT_LE_SHORT, pos);
            } catch (IndexOutOfBoundsException e) {
                throw handlePositionalIOOBE(e, "read", pos);
            } catch (NullPointerException | IllegalStateException e) {
                throw alreadyClosed(e);
            }
        }

        @Override
        public int readInt(long pos) throws IOException {
            try {
                // Decrypt 4 bytes for int
                long addr = curSegment.address() + pos;
                decryptAndProtect(decryptedPages, addr, 4, pos, keyIvResolver.getDataKey().getEncoded(), keyIvResolver.getIvBytes());

                return curSegment.get(LAYOUT_LE_INT, pos);
            } catch (IndexOutOfBoundsException e) {
                throw handlePositionalIOOBE(e, "read", pos);
            } catch (NullPointerException | IllegalStateException e) {
                throw alreadyClosed(e);
            } catch (Throwable e) {
                throw new IOException("Decryption failed", e);
            }
        }

        @Override
        public long readLong(long pos) throws IOException {
            try {
                // Decrypt 8 bytes for long
                long addr = curSegment.address() + pos;
                decryptAndProtect(decryptedPages, addr, 8, pos, keyIvResolver.getDataKey().getEncoded(), keyIvResolver.getIvBytes());

                return curSegment.get(LAYOUT_LE_LONG, pos);
            } catch (IndexOutOfBoundsException e) {
                throw handlePositionalIOOBE(e, "read", pos);
            } catch (NullPointerException | IllegalStateException e) {
                throw alreadyClosed(e);
            } catch (Throwable e) {
                throw new IOException("Decryption failed", e);
            }
        }
    }

    /**
     * This class adds offset support to MemorySegmentIndexInput, which is
     * needed for slices.
     */
    static final class MultiSegmentImpl extends MemorySegmentIndexInput {

        private final long offset;

        MultiSegmentImpl(
            String resourceDescription,
            Arena arena,
            MemorySegment[] segments,
            long offset,
            long length,
            int chunkSizePower,
            KeyIvResolver keyIvResolver,
            ConcurrentHashMap<Long, Boolean> decryptedPages

        ) {
            super(resourceDescription, arena, segments, length, chunkSizePower, keyIvResolver, decryptedPages);
            this.offset = offset;
            try {
                seek(0L);
            } catch (IOException ioe) {
                throw new AssertionError(ioe);
            }
            assert curSegment != null && curSegmentIndex >= 0;
        }

        @Override
        RuntimeException handlePositionalIOOBE(RuntimeException unused, String action, long pos) throws IOException {
            return super.handlePositionalIOOBE(unused, action, pos - offset);
        }

        @Override
        public void seek(long pos) throws IOException {
            assert pos >= 0L : "negative position";
            super.seek(pos + offset);
        }

        @Override
        public long getFilePointer() {
            return super.getFilePointer() - offset;
        }

        @Override
        public byte readByte(long pos) throws IOException {
            return super.readByte(pos + offset);
        }

        @Override
        public short readShort(long pos) throws IOException {
            return super.readShort(pos + offset);
        }

        @Override
        public int readInt(long pos) throws IOException {
            return super.readInt(pos + offset);
        }

        @Override
        public long readLong(long pos) throws IOException {
            return super.readLong(pos + offset);
        }

        @Override
        MemorySegmentIndexInput buildSlice(String sliceDescription, long ofs, long length) {
            return super.buildSlice(sliceDescription, this.offset + ofs, length);
        }
    }
}
