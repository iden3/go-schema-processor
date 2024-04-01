module github.com/iden3/go-schema-processor/v2

go 1.18

require (
	github.com/iden3/go-iden3-core/v2 v2.1.0
	github.com/iden3/go-iden3-crypto v0.0.15
	github.com/iden3/go-merkletree-sql/v2 v2.0.4
	// We require the `json-gold` bugfix which has not yet been included in the
	// stable version. After the release of version 0.5.1 or later, it will be
	// necessary to update to the stable version.
	// https://github.com/piprate/json-gold/commit/36fcca9d7e487684a764e552e7d837a14546a157
	github.com/piprate/json-gold v0.5.1-0.20230111113000-6ddbe6e6f19f
	github.com/pkg/errors v0.9.1
	github.com/pquerna/cachecontrol v0.0.0-20180517163645-1555304b9b35
	github.com/santhosh-tekuri/jsonschema/v5 v5.3.0
	github.com/stretchr/testify v1.8.4
	golang.org/x/crypto v0.12.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dchest/blake512 v1.0.0 // indirect
	github.com/mr-tron/base58 v1.2.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/sys v0.15.0 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
