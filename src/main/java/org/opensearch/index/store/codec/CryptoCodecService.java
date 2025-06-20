/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.codec;

import org.apache.lucene.codecs.Codec;
import org.opensearch.index.codec.CodecService;
import org.opensearch.index.codec.CodecServiceConfig;

public class CryptoCodecService extends CodecService {

    public CryptoCodecService(CodecServiceConfig codecServiceConfig) {
        super(codecServiceConfig.getMapperService(), codecServiceConfig.getIndexSettings(), codecServiceConfig.getLogger());
    }

    @Override
    public Codec codec(String name) {
        return new CryptoCodec();
    }
}
