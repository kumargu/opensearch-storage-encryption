/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.settings;

import java.security.Provider;
import java.security.Security;
import java.util.function.Function;

import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Setting.Property;
import org.opensearch.common.settings.SettingsException;

/**
 * Index-level settings for crypto storage.
 */
public class CryptoIndexSettings {

    /**
     * Enables encryption for the index. When true, the index will use encrypted storage.
     */
    public static final Setting<Boolean> INDEX_CRYPTO_ENABLED_SETTING = Setting
        .boolSetting("index.crypto.enabled", false, Property.IndexScope, Property.InternalIndex);

    /**
     * Specifies a crypto provider to be used for encryption. The default value
     * is SunJCE.
     */
    public static final Setting<Provider> INDEX_CRYPTO_PROVIDER_SETTING = new Setting<>("index.crypto.provider", "SunJCE", (s) -> {
        Provider p = Security.getProvider(s);
        if (p == null) {
            throw new SettingsException("unrecognized [index.crypto.provider] \"" + s + "\"");
        } else {
            return p;
        }
    }, Property.IndexScope, Property.InternalIndex);

    /**
     * Specifies the Key management plugin type to be used. The desired KMS
     * plugin should be installed.
     */
    public static final Setting<String> INDEX_KMS_TYPE_SETTING = new Setting<>(
        "index.crypto.keystore.type",
        "",
        Function.identity(),
        (s) -> {
            if (s == null || s.isEmpty()) {
                throw new SettingsException("index.crypto.keystore.type must be set");
            }
        },
        Property.NodeScope,
        Property.IndexScope
    );

    private CryptoIndexSettings() {
        // Utility class
    }
}
