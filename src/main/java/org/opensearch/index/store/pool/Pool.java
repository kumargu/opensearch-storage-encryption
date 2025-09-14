/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.pool;

import java.util.concurrent.TimeUnit;

public interface Pool<T> {
    T acquire() throws Exception;

    T tryAcquire(long timeout, TimeUnit unit) throws InterruptedException;

    void release(T pooled);

    long totalMemory();

    long availableMemory();

    int pooledSegmentSize();

    boolean isUnderPressure();

    void warmUp(long numBlocks);

    String poolStats();

    void close();

    boolean isClosed();
}
