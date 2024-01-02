module github.com/iden3/go-schema-processor/v2

go 1.18

require (
	github.com/google/uuid v1.3.0
	github.com/iden3/go-iden3-core/v2 v2.0.3
	github.com/iden3/go-iden3-crypto v0.0.15
	github.com/iden3/go-merkletree-sql/v2 v2.0.4
	github.com/ipfs/go-ipfs-api v0.6.0
	// We require the `json-gold` bugfix which has not yet been included in the
	// stable version. After the release of version 0.5.1 or later, it will be
	// necessary to update to the stable version.
	// https://github.com/piprate/json-gold/commit/36fcca9d7e487684a764e552e7d837a14546a157
	github.com/piprate/json-gold v0.5.1-0.20230111113000-6ddbe6e6f19f
	github.com/pkg/errors v0.9.1
	github.com/pquerna/cachecontrol v0.0.0-20180517163645-1555304b9b35
	github.com/santhosh-tekuri/jsonschema/v5 v5.3.0
	github.com/stretchr/testify v1.8.2
	golang.org/x/crypto v0.7.0
)

require (
	github.com/benbjohnson/clock v1.3.5 // indirect
	github.com/crackcomm/go-gitignore v0.0.0-20170627025303-887ab5e44cc3 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dchest/blake512 v1.0.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.2.0 // indirect
	github.com/ipfs/boxo v0.8.0 // indirect
	github.com/ipfs/go-cid v0.4.1 // indirect
	github.com/klauspost/cpuid/v2 v2.2.5 // indirect
	github.com/libp2p/go-buffer-pool v0.1.0 // indirect
	github.com/libp2p/go-flow-metrics v0.1.0 // indirect
	github.com/libp2p/go-libp2p v0.28.1 // indirect
	github.com/minio/sha256-simd v1.0.1 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/mr-tron/base58 v1.2.0 // indirect
	github.com/multiformats/go-base32 v0.1.0 // indirect
	github.com/multiformats/go-base36 v0.2.0 // indirect
	github.com/multiformats/go-multiaddr v0.9.0 // indirect
	github.com/multiformats/go-multibase v0.2.0 // indirect
	github.com/multiformats/go-multicodec v0.9.0 // indirect
	github.com/multiformats/go-multihash v0.2.2 // indirect
	github.com/multiformats/go-multistream v0.4.1 // indirect
	github.com/multiformats/go-varint v0.0.7 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/spaolacci/murmur3 v1.1.0 // indirect
	github.com/whyrusleeping/tar-utils v0.0.0-20201201191210-20a61371de5b // indirect
	golang.org/x/sys v0.8.0 // indirect
	google.golang.org/protobuf v1.30.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	lukechampine.com/blake3 v1.2.1 // indirect
)
