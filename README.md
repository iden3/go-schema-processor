# go-schema-processor

[![Go Reference](https://pkg.go.dev/badge/github.com/iden3/go-schema-processor.svg)](https://pkg.go.dev/github.com/iden3/go-schema-processor)
[![Go Report Card](https://goreportcard.com/badge/github.com/iden3/go-schema-processor)](https://goreportcard.com/report/github.com/iden3/go-schema-processor)
[![Test](https://github.com/iden3/go-schema-processor/actions/workflows/ci-test.yaml/badge.svg)](https://github.com/iden3/go-schema-processor/actions/workflows/ci-test.yaml)
[![Lint](https://github.com/iden3/go-schema-processor/actions/workflows/ci-lint.yaml/badge.svg)](https://github.com/iden3/go-schema-processor/actions/workflows/ci-lint.yaml)

### General description:

> Library goal is to create claim data slots according to the core claim specification from the W3C Verifiable Credential ([https://idocs.iden3.io/#/core/spec/spec](https://www.notion.so/Core-Spec-2ac887d1587c412cace6d44abe3ab148))
>

We use a common approach to describe data for Iden3 credentials by utilizing the concept of JSON-LD and JSON schemas.

Repository of claim schema vocabulary: https://github.com/iden3/claim-schema-vocab

The library includes three main components of any processor:

1. Data Validators
2. Data Parsers

**Schemas:**

JSON-LD schema do not define a Serialization type.

Also, json-ld schemas now are only responsible for field path resolution for merklization and field description.
The purpose of the JSON LD Schema is to define the explanation of the field and types by giving the corresponding vocabulary.

**Json LD Schema matters for the core claim. The hash of the url and W3C credential type goes into the core claim as a schema hash**

- Example of JSON-LD schema for Auth BJJ Credential

    ```json
  {
    "@context": [
            {
              "@version": 1.1,
              "@protected": true,
              "id": "@id",
              "type": "@type",
              "AuthBJJCredential": {
                "@id": "https://schema.iden3.io/core/jsonld/auth.jsonld#AuthBJJCredential",
                "@context": {
                  "@version": 1.1,
                  "@protected": true,
                  "id": "@id",
                  "type": "@type",
                  "xsd": "http://www.w3.org/2001/XMLSchema#",
                  "auth-vocab": "https://schema.iden3.io/core/vocab/auth.md#",
                  "x": {
                    "@id": "auth-vocab:x",
                    "@type": "xsd:string"
                  },
                  "y": {
                    "@id": "auth-vocab:y",
                    "@type": "xsd:string"
                  }
                }
              }
          }
      ]
  }


Each schema defines the type of credential e.g. `AuthBJJCredential`

`AuthBJJCredential` has next fields : `x` and `y` which are big integers represented as a string.

**JSON schemas**

How do we define which approach should be used when we create a core claim from a credential? (merklized or serialized)
We use JSON schemas!
According to the metadata field, if serialization persists we use its content to create a core claim, otherwise, we apply the algorithm of merklization.
Example of JSON schema for Credential

```json
 {
          "$schema": "http://json-schema.org/draft-07/schema#",
          "$metadata": {
            "uris": {
              "jsonLdContext": "https://schema.iden3.io/core/jsonld/auth.jsonld",
              "jsonSchema": "https://schema.iden3.io/core/json/auth.json"
            },
            "serialization": {
              "indexDataSlotA": "x",
              "indexDataSlotB": "y"
            }
          },
          "type": "object",
          "required": [
            "@context",
            "id",
            "type",
            "issuanceDate",
            "credentialSubject",
            "credentialSchema",
            "credentialStatus",
            "issuer"
          ],
          "properties": {
            "@context": {
              "type": [
                "string",
                "array",
                "object"
              ]
            },
            "id": {
              "type": "string"
            },
            "type": {
              "type": [
                "string",
                "array"
              ],
              "items": {
                "type": "string"
              }
            },
            "issuer": {
              "type": [
                "string",
                "object"
              ],
              "format": "uri",
              "required": [
                "id"
              ],
              "properties": {
                "id": {
                  "type": "string",
                  "format": "uri"
                }
              }
            },
            "issuanceDate": {
              "type": "string",
              "format": "date-time"
            },
            "expirationDate": {
              "type": "string",
              "format": "date-time"
            },
            "credentialSchema": {
              "type": "object",
              "required": [
                "id",
                "type"
              ],
              "properties": {
                "id": {
                  "type": "string",
                  "format": "uri"
                },
                "type": {
                  "type": "string"
                }
              }
            },
            "credentialSubject": {
              "type": "object",
              "required": [
                "x",
                "y"
              ],
              "properties": {
                "id": {
                  "title": "Credential Subject ID",
                  "type": "string",
                  "format": "uri"
                },
                "x": {
                  "type": "string"
                },
                "y": {
                  "type": "string"
                }
              }
            }
          }
        }
```

From this schema, JSON processor will extract fields name for Index slots ("countryCode","documentType")  and for Value slots (none)

**Validators:**

Validators implement method `ValidateData`

Their purpose is to restrict possible invalid data to be processed by the parser.

**Parsers**:

The parser is the main part of this library.
There is one implementation of JSON parse for now.

## Contributing

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as below, without any additional terms or conditions.

## License

&copy; 2023 0kims Association

This project is licensed under either of

- [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([`LICENSE-APACHE`](LICENSE-APACHE))
- [MIT license](https://opensource.org/licenses/MIT) ([`LICENSE-MIT`](LICENSE-MIT))

at your option.
