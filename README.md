# opensearch-storage-encryption

An Opensearch plugin for supporting "fast" On fly Index-Level-Encryption. Security with high Performance is of highest 
prority. 


# Architecture

```


Node 

┌─────────────┐                 ┌─────────────────────────────────────────────┐                 
│   Tenant A  │                 │             OpenSearch App                  │                                      
│ (plain text)│ ────plain────→  │                                             │                                            
└─────────────┘                 │  ┌─────────────────┐      plain text        │  ┌─────────────┐│                            
                                │  │ HybridDirectory │ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─→ │  Tenant A   ││
                                │  │                 │                         │  │   index     ││
                                │  └─────────────────┘                         │  │   shards    ││
                                │                                              │  └─────────────┘│
┌─────────────┐                 │                                              │  ┌─────────────┐│
│   Tenant B  │                 │  ┌─────────────────┐      cipher text        │  │  Tenant B   ││
│ (encrypted) │ ────plain────→  │  │ CryptoDirectory │ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═→ │   index     ││
└─────────────┘                 │  │      🔑         │                         │  │   shards    ││
                                │  └─────────────────┘                         │  │     🔑      ││
                                │           │                                  │  └─────────────┘│
                                └───────────┼──────────────────────────────────┘                 
                                            ▼ generate or decrypt                               
                                             data key                                           
                                ┌─────────────────────────┐                                     
                                │    Tenant B KMS (🔐)     │                                     
                                │   Key Management Service │                                     
                                └─────────────────────────┘                                     
                                                                                               

```



## Key Components

We implement a new Lucene Directory (NioFS and MMAP) that will encrypt or decrypt shard data on the fly. We can use existing settings.index.store.type configuration to enable encryption when we create an index. Currently we only support KMS for key management but it can be extended in future

For example:

```
 "index_settings": {
    "index.store.type": "cryptofs",
    "index.store.crypto.key.type": "aws-kms",
    "index.store.crypto.key": "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012"
}

```

Settings:
- `index.store.crypto.key.type`: The type of KMS provider (e.g., "aws-kms", "dummy")
- `index.store.crypto.key`: The KMS key ID/ARN to use for encryption (optional, depends on KMS provider)

## Key announcement  

29/7/2025: The plugin development is still in progress and is expected to land fully in Opensearch 3.3 release.

