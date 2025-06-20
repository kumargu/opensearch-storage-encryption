/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.codec;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.codecs.Codec;
import org.apache.lucene.codecs.DocValuesConsumer;
import org.apache.lucene.codecs.DocValuesFormat;
import org.apache.lucene.codecs.FieldsConsumer;
import org.apache.lucene.codecs.FilterCodec;
import org.apache.lucene.codecs.NormsConsumer;
import org.apache.lucene.codecs.NormsFormat;
import org.apache.lucene.codecs.PointsFormat;
import org.apache.lucene.codecs.PointsWriter;
import org.apache.lucene.codecs.PostingsFormat;
import org.apache.lucene.codecs.StoredFieldsFormat;
import org.apache.lucene.codecs.StoredFieldsWriter;
import org.apache.lucene.codecs.TermVectorsFormat;
import org.apache.lucene.codecs.TermVectorsWriter;
import org.apache.lucene.index.SegmentInfo;
import org.apache.lucene.index.SegmentWriteState;
import org.apache.lucene.store.Directory;
import org.apache.lucene.store.IOContext;

/**
 * Shared registry for SegmentInfo that can be accessed by CryptoNIOFSDirectory
 */
class CryptoSegmentRegistry {
    // this will be shared between all directory implementations. 
    // for now, hack and just spin a new hashmap. 
    private static final Map<String, SegmentInfo> SEGMENT_REGISTRY = new ConcurrentHashMap<>();

    public static void register(SegmentInfo segmentInfo) { 
        SEGMENT_REGISTRY.put(segmentInfo.name, segmentInfo);
    }

    public static SegmentInfo getSegmentInfo(String segmentName) {
        return SEGMENT_REGISTRY.get(segmentName);
    }
}

public class CryptoCodec extends FilterCodec {

    private static final Logger LOGGER = LogManager.getLogger(CryptoCodec.class);

    public CryptoCodec() {
        super("CryptoCodec", Codec.getDefault());
    }

    @Override
    public StoredFieldsFormat storedFieldsFormat() {
        return new CryptoStoredFieldsFormat();
    }

    @Override
    public TermVectorsFormat termVectorsFormat() {
        return new CryptoTermVectorsFormat();
    }

    @Override
    public DocValuesFormat docValuesFormat() {
        return new CryptoDocValuesFormat();
    }

    @Override
    public NormsFormat normsFormat() {
        return new CryptoNormsFormat();
    }

    @Override
    public PointsFormat pointsFormat() {
        return new CryptoPointsFormat();
    }

    @Override
    public PostingsFormat postingsFormat() {
        return new CryptoPostingsFormat();
    }

    private void processSegmentInfo(SegmentInfo segmentInfo) {
        segmentInfo.putAttribute("encryption_algorithm", "AES-256-CTR");
        segmentInfo.putAttribute("encrypted_timestamp", String.valueOf(System.currentTimeMillis()));

        // Register in shared registry for CryptoNIOFSDirectory to access
        CryptoSegmentRegistry.register(segmentInfo);

        LOGGER.info("Processed SegmentInfo for segment: {} ", segmentInfo.toString());
    }

    private class CryptoStoredFieldsFormat extends StoredFieldsFormat {
        @Override
        public StoredFieldsWriter fieldsWriter(Directory directory, SegmentInfo si, IOContext context) throws IOException {
            processSegmentInfo(si);
            return delegate.storedFieldsFormat().fieldsWriter(directory, si, context);
        }

        // Reader uses default behavior - no special handling needed
        @Override
        public org.apache.lucene.codecs.StoredFieldsReader fieldsReader(
            Directory directory,
            SegmentInfo segmentInfo,
            org.apache.lucene.index.FieldInfos fieldInfos,
            IOContext context
        ) throws IOException {
            return delegate.storedFieldsFormat().fieldsReader(directory, segmentInfo, fieldInfos, context);
        }
    }

    private class CryptoTermVectorsFormat extends TermVectorsFormat {
        @Override
        public TermVectorsWriter vectorsWriter(Directory directory, SegmentInfo segmentInfo, IOContext context) throws IOException {
            processSegmentInfo(segmentInfo);
            return delegate.termVectorsFormat().vectorsWriter(directory, segmentInfo, context);
        }

        @Override
        public org.apache.lucene.codecs.TermVectorsReader vectorsReader(
            Directory directory,
            SegmentInfo segmentInfo,
            org.apache.lucene.index.FieldInfos fieldInfos,
            IOContext context
        ) throws IOException {
            return delegate.termVectorsFormat().vectorsReader(directory, segmentInfo, fieldInfos, context);
        }
    }

    private class CryptoDocValuesFormat extends DocValuesFormat {
        protected CryptoDocValuesFormat() {
            super("CryptoDocValues");
        }

        @Override
        public DocValuesConsumer fieldsConsumer(SegmentWriteState state) throws IOException {
            processSegmentInfo(state.segmentInfo);
            return delegate.docValuesFormat().fieldsConsumer(state);
        }

        @Override
        public org.apache.lucene.codecs.DocValuesProducer fieldsProducer(org.apache.lucene.index.SegmentReadState state)
            throws IOException {
            return delegate.docValuesFormat().fieldsProducer(state);
        }
    }

    private class CryptoNormsFormat extends NormsFormat {
        @Override
        public NormsConsumer normsConsumer(SegmentWriteState state) throws IOException {
            processSegmentInfo(state.segmentInfo);
            return delegate.normsFormat().normsConsumer(state);
        }

        @Override
        public org.apache.lucene.codecs.NormsProducer normsProducer(org.apache.lucene.index.SegmentReadState state) throws IOException {
            return delegate.normsFormat().normsProducer(state);
        }
    }

    private class CryptoPointsFormat extends PointsFormat {
        @Override
        public PointsWriter fieldsWriter(SegmentWriteState state) throws IOException {
            processSegmentInfo(state.segmentInfo);
            return delegate.pointsFormat().fieldsWriter(state);
        }

        @Override
        public org.apache.lucene.codecs.PointsReader fieldsReader(org.apache.lucene.index.SegmentReadState state) throws IOException {
            return delegate.pointsFormat().fieldsReader(state);
        }
    }

    private class CryptoPostingsFormat extends PostingsFormat {
        protected CryptoPostingsFormat() {
            super("CryptoPostings");
        }

        @Override
        public FieldsConsumer fieldsConsumer(SegmentWriteState state) throws IOException {
            processSegmentInfo(state.segmentInfo);
            return delegate.postingsFormat().fieldsConsumer(state);
        }

        @Override
        public org.apache.lucene.codecs.FieldsProducer fieldsProducer(org.apache.lucene.index.SegmentReadState state) throws IOException {
            return delegate.postingsFormat().fieldsProducer(state);
        }
    }
}
