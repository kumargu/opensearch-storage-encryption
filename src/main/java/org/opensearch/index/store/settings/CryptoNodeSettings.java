/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.settings;

import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Setting.Property;
import org.opensearch.core.common.unit.ByteSizeValue;

/**
 * Node-level settings for crypto storage.
 */
public class CryptoNodeSettings {

    /**
     * Specifies the node-level TTL for data keys in seconds.
     * Default is 3600 seconds (1 hour).
     * Set to -1 to disable key refresh (keys are loaded once and cached forever).
     * This setting applies globally to all indices.
     */
    public static final Setting<Integer> NODE_DATA_KEY_TTL_SECONDS_SETTING = Setting
        .intSetting(
            "node.store.data_key_ttl_seconds",
            3600,  // default: 3600 seconds (1 hour)
            -1,    // minimum: -1 means never refresh
            (value) -> {
                if (value != -1 && value < 1) {
                    throw new IllegalArgumentException("node.store.data_key_ttl_seconds must be -1 (never refresh) or a positive value");
                }
            },
            Property.NodeScope
        );

    /**
     * Specifies the reserved pool size in bytes for Direct I/O operations.
     * Default is 32GB.
     */
    public static final Setting<ByteSizeValue> NODE_RESERVED_POOL_SIZE_SETTING = Setting
        .byteSizeSetting("node.store.directio.pool_size", new ByteSizeValue(32L * 1024 * 1024 * 1024), Property.NodeScope);

    /**
     * Specifies the warm-up percentage for the memory pool.
     * Default is 0.2 (20%).
     */
    public static final Setting<Double> NODE_POOL_WARMUP_PERCENTAGE_SETTING = Setting
        .doubleSetting("node.store.directio.pool_warmup_percentage", 0.2, 0.0, 1.0, Property.NodeScope);

    /**
     * Specifies the block size power for cache blocks (block size = 2^power).
     * Default is 13 (8KB blocks).
     */
    public static final Setting<Integer> NODE_CACHE_BLOCK_SIZE_POWER_SETTING = Setting
        .intSetting("node.store.directio.cache_block_size_power", 13, 12, Property.NodeScope);

    /**
     * Specifies the initial size for the cache.
     * Default is 65536.
     */
    public static final Setting<Integer> NODE_CACHE_INITIAL_SIZE_SETTING = Setting
        .intSetting("node.store.directio.cache_initial_size", 65536, 1024, Property.NodeScope);

    /**
     * Specifies the read-ahead queue size.
     * Default is 4096.
     */
    public static final Setting<Integer> NODE_READ_AHEAD_QUEUE_SIZE_SETTING = Setting
        .intSetting("node.store.directio.read_ahead_queue_size", 4096, 256, Property.NodeScope);

    private CryptoNodeSettings() {
        // Utility class
    }
}
