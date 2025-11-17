/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store;

import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;

import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.common.io.stream.NamedWriteableRegistry;
import org.opensearch.core.index.Index;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.env.Environment;
import org.opensearch.env.NodeEnvironment;
import org.opensearch.index.IndexModule;
import org.opensearch.index.IndexSettings;
import org.opensearch.index.engine.EngineFactory;
import org.opensearch.index.shard.IndexEventListener;
import org.opensearch.index.store.block_cache.BlockCache;
import org.opensearch.index.store.key.NodeLevelKeyCache;
import org.opensearch.index.store.key.ShardKeyResolverRegistry;
import org.opensearch.index.store.metrics.CryptoMetricsService;
import org.opensearch.index.store.pool.PoolBuilder;
import org.opensearch.index.store.pool.PoolSizeCalculator;
import org.opensearch.indices.cluster.IndicesClusterStateService.AllocatedIndices.IndexRemovalReason;
import org.opensearch.plugins.EnginePlugin;
import org.opensearch.plugins.IndexStorePlugin;
import org.opensearch.plugins.Plugin;
import org.opensearch.plugins.TelemetryAwarePlugin;
import org.opensearch.repositories.RepositoriesService;
import org.opensearch.script.ScriptService;
import org.opensearch.telemetry.metrics.MetricsRegistry;
import org.opensearch.telemetry.tracing.Tracer;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;
import org.opensearch.watcher.ResourceWatcherService;

/**
 * Index-level encryption plugin that wraps the default DirectoryFactory
 * when "index.store.crypto.enabled = true".
 */
public class CryptoDirectoryPlugin extends Plugin implements IndexStorePlugin, EnginePlugin, TelemetryAwarePlugin {

    private PoolBuilder.PoolResources sharedPoolResources;
    private NodeEnvironment nodeEnvironment;

    @Override
    public List<Setting<?>> getSettings() {
        return Arrays
            .asList(
                // plugin settings
                CryptoDirectoryFactory.INDEX_CRYPTO_ENABLED_SETTING,
                CryptoDirectoryFactory.INDEX_KEY_PROVIDER_SETTING,
                CryptoDirectoryFactory.INDEX_CRYPTO_PROVIDER_SETTING,
                CryptoDirectoryFactory.INDEX_KMS_ARN_SETTING,
                CryptoDirectoryFactory.INDEX_KMS_ENC_CTX_SETTING,
                CryptoDirectoryFactory.NODE_KEY_REFRESH_INTERVAL_SECS_SETTING,
                // pool + cache size tuning
                PoolSizeCalculator.NODE_POOL_SIZE_PERCENTAGE_SETTING,
                PoolSizeCalculator.NODE_CACHE_TO_POOL_RATIO_SETTING,
                PoolSizeCalculator.NODE_WARMUP_PERCENTAGE_SETTING
            );
    }

    /**
     * Register directory factories for standard store types.
     * The factory checks INDEX_CRYPTO_ENABLED flag to decide whether to encrypt.
     */
    @Override
    public Map<String, DirectoryFactory> getDirectoryFactories() {
        CryptoDirectoryFactory factory = new CryptoDirectoryFactory();
        Map<String, DirectoryFactory> factories = new HashMap<>();

        // register factory for all known store types
        for (IndexModule.Type t : IndexModule.Type.values()) {
            factories.put(t.getSettingsKey(), factory);
        }

        return factories;
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
        Supplier<RepositoriesService> repositoriesServiceSupplier,
        Tracer tracer,
        MetricsRegistry metricsRegistry
    ) {
        this.nodeEnvironment = nodeEnvironment;

        // Initialize shared resources
        sharedPoolResources = CryptoDirectoryFactory.initializeSharedPool(environment.settings());
        NodeLevelKeyCache.initialize(environment.settings());
        CryptoMetricsService.initialize(metricsRegistry);

        return Collections.emptyList();
    }

    @Override
    public void close() {
        if (sharedPoolResources != null) {
            sharedPoolResources.close();
        }
    }

    @Override
    public void onIndexModule(IndexModule indexModule) {
        Settings idxSettings = indexModule.getSettings();
        boolean cryptoEnabled = CryptoDirectoryFactory.INDEX_CRYPTO_ENABLED_SETTING.get(idxSettings);

        if (cryptoEnabled == false) {
            return; // normal store behavior
        }

        // install deletion + resolver pruning logic for encrypted indices
        indexModule.addIndexEventListener(new IndexEventListener() {
            @Override
            public void afterIndexRemoved(Index index, IndexSettings settings, IndexRemovalReason reason) {
                if (reason != IndexRemovalReason.DELETED) {
                    return;
                }

                // invalidate cache entries for that index
                BlockCache<?> cache = CryptoDirectoryFactory.getSharedBlockCache();
                if (cache != null && nodeEnvironment != null) {
                    for (Path indexPath : nodeEnvironment.indexPaths(index)) {
                        cache.invalidateByPathPrefix(indexPath);
                    }
                }

                // remove shard-key resolvers
                int nShards = settings.getNumberOfShards();
                for (int i = 0; i < nShards; i++) {
                    ShardKeyResolverRegistry.removeResolver(index.getUUID(), i);
                }
            }
        });
    }

    /**
     * EngineFactory (optional override).
     * If you want a custom engine, plug it in here.
     * For now, we only override the directory layer.
     */
    @Override
    public Optional<EngineFactory> getEngineFactory(IndexSettings indexSettings) {
        boolean cryptoEnabled = CryptoDirectoryFactory.INDEX_CRYPTO_ENABLED_SETTING.get(indexSettings.getSettings());

        if (cryptoEnabled) {
            return Optional.of(new CryptoEngineFactory());
        }

        return Optional.empty();
    }
}
