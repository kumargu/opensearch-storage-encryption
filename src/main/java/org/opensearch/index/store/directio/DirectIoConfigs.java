/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.directio;

import org.opensearch.common.settings.Settings;
import org.opensearch.index.store.PanamaNativeAccess;
import org.opensearch.index.store.settings.CryptoNodeSettings;

public class DirectIoConfigs {
    public static final int DIRECT_IO_ALIGNMENT = Math.max(512, PanamaNativeAccess.getPageSize());
    public static final int DIRECT_IO_WRITE_BUFFER_SIZE_POWER = 18;

    // Mutable static fields - initialized from settings
    public static long RESEVERED_POOL_SIZE_IN_BYTES;
    public static double WARM_UP_PERCENTAGE;
    public static int CACHE_BLOCK_SIZE_POWER;
    public static int CACHE_BLOCK_SIZE;
    public static long CACHE_BLOCK_MASK;
    public static int CACHE_INITIAL_SIZE;
    public static int READ_AHEAD_QUEUE_SIZE;

    static {
        // Initialize with defaults
        initialize(Settings.EMPTY);
    }

    /**
     * Initialize DirectIoConfigs with actual settings.
     * Should be called early during node startup with node settings.
     */
    public static synchronized void initialize(Settings settings) {
        RESEVERED_POOL_SIZE_IN_BYTES = CryptoNodeSettings.NODE_RESERVED_POOL_SIZE_SETTING.get(settings).getBytes();
        WARM_UP_PERCENTAGE = CryptoNodeSettings.NODE_POOL_WARMUP_PERCENTAGE_SETTING.get(settings);
        CACHE_BLOCK_SIZE_POWER = CryptoNodeSettings.NODE_CACHE_BLOCK_SIZE_POWER_SETTING.get(settings);
        CACHE_BLOCK_SIZE = 1 << CACHE_BLOCK_SIZE_POWER;
        CACHE_BLOCK_MASK = CACHE_BLOCK_SIZE - 1;
        CACHE_INITIAL_SIZE = CryptoNodeSettings.NODE_CACHE_INITIAL_SIZE_SETTING.get(settings);
        READ_AHEAD_QUEUE_SIZE = CryptoNodeSettings.NODE_READ_AHEAD_QUEUE_SIZE_SETTING.get(settings);
    }
}
