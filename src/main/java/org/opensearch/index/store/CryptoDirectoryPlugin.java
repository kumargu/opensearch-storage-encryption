/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;

import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Setting;
import org.opensearch.core.common.io.stream.NamedWriteableRegistry;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.env.Environment;
import org.opensearch.env.NodeEnvironment;
import org.opensearch.index.IndexModule;
import org.opensearch.index.IndexService;
import org.opensearch.index.IndexSettings;
import org.opensearch.index.engine.EngineFactory;
import org.opensearch.index.shard.IndexEventListener;
import org.opensearch.index.store.directio.DirectIoConfigs;
import org.opensearch.index.store.iv.IndexKeyResolverRegistry;
import org.opensearch.index.store.iv.NodeLevelKeyCache;
import org.opensearch.index.store.settings.CryptoIndexSettings;
import org.opensearch.index.store.settings.CryptoNodeSettings;
import org.opensearch.indices.cluster.IndicesClusterStateService.AllocatedIndices.IndexRemovalReason;
import org.opensearch.plugins.EnginePlugin;
import org.opensearch.plugins.IndexStorePlugin;
import org.opensearch.plugins.Plugin;
import org.opensearch.repositories.RepositoriesService;
import org.opensearch.script.ScriptService;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;
import org.opensearch.watcher.ResourceWatcherService;

/**
 * A plugin that enables index-level encryption and decryption.
 *
 * Encryption is enabled via the {@code index.crypto.enabled} setting.
 * When enabled, the CryptoDirectoryFactory wraps the underlying directory implementation.
 */
public class CryptoDirectoryPlugin extends Plugin implements IndexStorePlugin, EnginePlugin {

    public CryptoDirectoryPlugin() {
        super();
    }

    @Override
    public List<Setting<?>> getSettings() {
        return Arrays
            .asList(
                CryptoIndexSettings.INDEX_CRYPTO_ENABLED_SETTING,
                CryptoIndexSettings.INDEX_KMS_TYPE_SETTING,
                CryptoIndexSettings.INDEX_CRYPTO_PROVIDER_SETTING,
                CryptoNodeSettings.NODE_DATA_KEY_TTL_SECONDS_SETTING,
                CryptoNodeSettings.NODE_RESERVED_POOL_SIZE_SETTING,
                CryptoNodeSettings.NODE_POOL_WARMUP_PERCENTAGE_SETTING,
                CryptoNodeSettings.NODE_CACHE_BLOCK_SIZE_POWER_SETTING,
                CryptoNodeSettings.NODE_CACHE_INITIAL_SIZE_SETTING,
                CryptoNodeSettings.NODE_READ_AHEAD_QUEUE_SIZE_SETTING
            );
    }

    /**
     * Register CryptoDirectoryFactory for all built-in store types.
     * The factory internally checks index.crypto.enabled and delegates to
     * the default factory if encryption is not enabled.
     */
    @Override
    public Map<String, DirectoryFactory> getDirectoryFactories() {
        Map<String, DirectoryFactory> factories = new java.util.HashMap<>();
        CryptoDirectoryFactory cryptoFactory = new CryptoDirectoryFactory();

        // Register for all store types - factory will check index.crypto.enabled flag
        for (IndexModule.Type type : IndexModule.Type.values()) {
            if (type != IndexModule.Type.REMOTE_SNAPSHOT) {
                factories.put(type.getSettingsKey(), cryptoFactory);
            }
        }

        return factories;
    }

    @Override
    public Optional<EngineFactory> getEngineFactory(IndexSettings indexSettings) {
        if (indexSettings.getValue(CryptoIndexSettings.INDEX_CRYPTO_ENABLED_SETTING)) {
            return Optional.of(new CryptoEngineFactory());
        }
        return Optional.empty();
    }

    @Override
    public Collection<Object> createComponents(
        Client client,
        ClusterService clusterService,
        ThreadPool threadPool,
        ResourceWatcherService resourceWatcherService,
        ScriptService scriptService,
        NamedXContentRegistry xContentRegistry,
        Environment environment,
        NodeEnvironment nodeEnvironment,
        NamedWriteableRegistry namedWriteableRegistry,
        IndexNameExpressionResolver expressionResolver,
        Supplier<RepositoriesService> repositoriesServiceSupplier
    ) {
        // Initialize DirectIO and crypto pools at node startup
        DirectIoConfigs.initialize(environment.settings());
        CryptoDirectoryFactory.initializeSharedPool();
        NodeLevelKeyCache.initialize(environment.settings());
        return Collections.emptyList();
    }

    @Override
    public void onIndexModule(IndexModule indexModule) {
        // Add cleanup listener for all indices (will only clean up if resolver exists)
        indexModule.addIndexEventListener(new IndexEventListener() {
            @Override
            public void beforeIndexRemoved(IndexService indexService, IndexRemovalReason reason) {
                String indexUuid = indexService.index().getUUID();
                IndexKeyResolverRegistry.removeResolver(indexUuid);
            }
        });
    }

}
