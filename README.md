# go-claim-schema-processor

[![Go Reference](https://pkg.go.dev/badge/github.com/iden3/go-claim-schema-processor.svg)](https://pkg.go.dev/github.com/iden3/go-claim-schema-processor)
[![Go Report Card](https://goreportcard.com/badge/github.com/iden3/go-claim-schema-processor)](https://goreportcard.com/report/github.com/iden3/go-claim-schema-processor)
[![Test](https://github.com/iden3/go-claim-schema-processor/actions/workflows/ci-test.yaml/badge.svg)](https://github.com/iden3/go-claim-schema-processor/actions/workflows/ci-test.yaml)
[![Lint](https://github.com/iden3/go-claim-schema-processor/actions/workflows/ci-lint.yaml/badge.svg)](https://github.com/iden3/go-claim-schema-processor/actions/workflows/ci-lint.yaml)

### General description:

> Library goal is to create claim data slots according to the claim specification ([https://idocs.iden3.io/#/core/spec/spec](https://www.notion.so/Core-Spec-2ac887d1587c412cace6d44abe3ab148))
>

We use a common approach to describe data for Iden3 credentials by utilizing the concept of JSON-LD and JSON schemas.

Repository of claim schema vocabulary: https://github.com/iden3/claim-schema-vocab

The library includes three main components of any processor:

1. Schema Loaders
2. Data Validators
3. Data Parsers

**Schema loader's** purpose is to load schema (JSON / JSON-LD) from a given address.

Implemented loaders:

- [x]  HTTP loaders
- [ ]  IPFS  loader

**Schema examples:**

JSON-ld:

- Example of JSON-LD schema for KYC

    ```json
    {
      "@context": [
        {
          "@version": 1.1,
          "@protected": true,
          "id": "@id",
          "type": "@type",
          "KYCCountryOfResidenceCredential": {
            "@id": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc.json-ld#KYCCountryOfResidenceCredential",
            "@context": {
              "@version": 1.1,
              "@protected": true,
              "id": "@id",
              "type": "@type",
              "kyc-vocab": "https://github.com/iden3/claim-schema-vocab/blob/main/credentials/kyc.md#",
              "serialization": "https://github.com/iden3/claim-schema-vocab/blob/main/credentials/serialization.md#",
              "countryCode": {
                "@id": "kyc-vocab:countryCode",
                "@type": "serialization:IndexDataSlotA"
              },
              "documentType": {
                "@id": "kyc-vocab:documentType",
                "@type": "serialization:IndexDataSlotB"
              }
            }
          }
        }
      ]
    }
    ```


Each schema defines the type of credential e.g. `KYCCountryOfResidenceCredential`

`KYCCountryOfResidenceCredential` has next fields : `countryCode` and `documentType`

Type of `countryCode` is determined by the `"serialization:IndexDataSlotA"` field.

That means, claim processor library will process data with property `countryCode` and will put it to the Index slot (A) of the claim.

JSON schemas

- Example of JSON schema for KYC

    ```json
    {
      "$schema": "http://json-schema.org/draft-07/schema#",
      "type": "object",
      "properties": {
        "countryCode": {
          "type": "integer"
        },
        "documentType": {
          "type": "integer"
        },
        "index": {
          "type": "array",
          "default":["countryCode","documentType"]
        },
        "value": {
          "type": "array",
          "default":[]
        }
      },
      "required": [
        "countryCode","documentType"
      ]
    }
    ```


From this schema, JSON processor will extract fields name for Index slots ("countryCode","documentType")  and for Value slots (none)

**Validators:**

Validators implement two methods: ValidateData and ValidateDocument

Their purpose is to restrict possible invalid data to be processed by the parser.

**Parsers**:

The parser is the main part of this library.
There are two implementations: JSON and JSON-LD

For each parser two parsing strategies exist:  `OneFieldPerSlotStrategy`  and `SlotFullfilmentStrategy`

If the parser is initialized with `OneFieldPerSlotStrategy` it will assign only one field from data to the claim a slot, in the case of `SlotFullfilmentStrategy` all capacity of the claim slot will be used (for several fields).

For JSON-LD parser claim type is required.

Examples:

```go
loader := loaders.HTTP{}
validator := json.Validator{}
parser := jsonld.Parser{ClaimType: "KYCAgeCredential", ParsingStrategy: processor.OneFieldPerSlotStrategy}

jsonLdProcessor := New(processor.WithValidator(validator), processor.WithParser(parser), processor.WithSchemaLoader(loader))

schema, _, err := jsonLdProcessor.Load(url) // Load schema

data := make(map[string]interface{})
data["birthday"] = 828522341
data["documentType"] = 1
dataBytes, err := commonJSON.Marshal(data)
assert.Nil(t, err)

err = p.ValidateData(dataBytes, schema)  // Validation of data
parsedData, err := jsonLdProcessor.ParseSlots(dataBytes, schema) // parsing data
```

As result, output of processor will be 4 claim slots

```go
type ParsedSlots struct {
	IndexA, IndexB []byte
	ValueA, ValueB []byte
}
```
