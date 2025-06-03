/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.mmap;

import org.apache.lucene.store.IOContext;
import org.apache.lucene.store.IOContext.Context;
import org.apache.lucene.store.ReadAdvice;

public class LuceneIOContextMAdvise {

    // madvise flags
    private static final int MADV_NORMAL = 0;
    private static final int MADV_RANDOM = 1;
    private static final int MADV_SEQUENTIAL = 2;
    private static final int MADV_WILLNEED = 3;
    private static final int MADV_DONTNEED = 4;

    /**
     * Get madvise flags based on Lucene's IOContext
     * 
     * Key insights from IOContext:
     * - MERGE context always uses SEQUENTIAL
     * - FLUSH context always uses SEQUENTIAL
     * - DEFAULT context can have RANDOM, SEQUENTIAL, or NORMAL
     * - READONCE is just DEFAULT with SEQUENTIAL
     */

    public static int getMAdviseFlags(IOContext context, String fileName) {
        if (context == null) {
            return MADV_NORMAL;
        }

        Context ctxType = context.context();
        ReadAdvice readAdvice = context.readAdvice();

        // Handle based on context type first
        switch (ctxType) {
            case MERGE:
                // Merges always sequential, free pages after reading
                return MADV_SEQUENTIAL | MADV_DONTNEED;

            case FLUSH:
                // Flushes are sequential writes/reads
                return MADV_SEQUENTIAL;

            case DEFAULT:
                // Check the actual readAdvice for DEFAULT context
                switch (readAdvice) {
                    case SEQUENTIAL:
                        return MADV_SEQUENTIAL;
                    case RANDOM:
                        return MADV_RANDOM;
                    case NORMAL:
                        return MADV_NORMAL;
                    default:
                        return MADV_NORMAL;
                }

            default:
                return MADV_NORMAL;
        }
    }

    private static int getSequentialAdvice(String fileName) {
        String fileType = getFileType(fileName);

        switch (fileType) {
            case "tim":
                // Sequential term dictionary scan - likely bulk operation
                return MADV_SEQUENTIAL | MADV_WILLNEED;

            case "doc":
                // Sequential postings read
                return MADV_SEQUENTIAL;

            case "dvd":
                // Sequential DocValues scan
                return MADV_SEQUENTIAL;

            case "kdd":
                // Sequential points scan - often one-time
                return MADV_SEQUENTIAL | MADV_DONTNEED;

            default:
                return MADV_SEQUENTIAL;
        }
    }

    private static int getRandomAdvice(String fileName) {
        String fileType = getFileType(fileName);

        switch (fileType) {
            case "tim":
                // Random term lookups - critical path
                return MADV_RANDOM | MADV_WILLNEED;

            case "doc":
                // Random postings access
                return MADV_RANDOM | MADV_WILLNEED;

            case "dvd":
                // Random DocValues access (sorting/faceting)
                return MADV_RANDOM;

            case "kdd":
                // Random points access (range queries)
                return MADV_RANDOM;

            default:
                return MADV_RANDOM;
        }
    }

    private static int getNormalAdvice(String fileName) {
        String fileType = getFileType(fileName);

        // NORMAL typically means mixed access patterns
        switch (fileType) {
            case "tim":
            case "doc":
                // These benefit from being in memory
                return MADV_WILLNEED;

            case "dvd":
            case "kdd":
                // Less critical, use OS default
                return MADV_NORMAL;

            default:
                return MADV_NORMAL;
        }
    }

    private static String getFileType(String fileName) {
        if (fileName.endsWith(".tim"))
            return "tim";
        if (fileName.endsWith(".doc"))
            return "doc";
        if (fileName.endsWith(".dvd"))
            return "dvd";
        if (fileName.endsWith(".kdd"))
            return "kdd";
        return "unknown";
    }

    private static String getFileExtension(String fileName) {
        int lastDot = fileName.lastIndexOf('.');
        return lastDot >= 0 ? fileName.substring(lastDot) : "";
    }

    public static boolean shouldPreload(String fileName, long fileSize) {
        String extension = getFileExtension(fileName);

        switch (extension) {
            case ".cfs":
                return fileSize <= (4L << 20);

            case ".tim":
                return fileSize <= (128L << 20);

            case ".doc":
                return fileSize <= (64L << 20);

            case ".dvd":
            case ".kdd":
                return false; // Don't preload - sequential access

            default:
                return fileSize <= (8L << 20);   // 10MB for others
        }
    }
}
