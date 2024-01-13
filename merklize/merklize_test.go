package merklize

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"text/template"
	"time"

	"github.com/iden3/go-iden3-crypto/constants"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-merkletree-sql/v2/db/memory"
	"github.com/iden3/go-schema-processor/v2/loaders"
	tst "github.com/iden3/go-schema-processor/v2/testing"
	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const nestedFieldDocument = `{
  "@context": [
    {
      "@version": 1.1,
      "@protected": true,
      "id": "@id",
      "type": "@type",
      "CustomType": {
        "@id": "urn:uuid:79f824ba-fee3-11ed-be56-0242ac120002",
        "@context": {
          "@version": 1.1,
          "@protected": true,
          "@propagate": true,
          "id": "@id",
          "type": "@type",
          "xsd": "http://www.w3.org/2001/XMLSchema#",
          "customField": {
            "@id": "polygon-vocab:customField",
            "@type": "xsd:string"
          },
          "polygon-vocab": "urn:uuid:87caf7a2-fee3-11ed-be56-0242ac120001#",
          "objectField": {
            "@id": "polygon-vocab:objectField",
            "@context": {
              "@version": 1.1,
              "@protected": true,
              "id": "@id",
              "type": "@type",
              "customNestedField": {
                "@id": "polygon-vocab:customNestedField",
                "@type": "xsd:integer"
              }
            }
          }
        }
      }
    }
  ],
  "id": "urn:urn:e27a921e-fee5-11ed-be56-0242ac100000",
  "type": ["CustomType"],
  "customField": "1234",
  "objectField": {
    "customNestedField": 1
  }
}`

var testDocumentURLMaps = map[string]string{
	"https://www.w3.org/2018/credentials/v1": "testdata/httpresp/credentials-v1.jsonld",
	"https://w3id.org/citizenship/v1":        "testdata/httpresp/citizenship-v1.json-ld",
	"https://w3id.org/security/bbs/v1":       "testdata/httpresp/bbs-v1.json-ld",
}

const testDocument = `{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/citizenship/v1",
	"https://w3id.org/security/bbs/v1"
  ],
  "id": "https://issuer.oidp.uscis.gov/credentials/83627465",
  "type": ["VerifiableCredential", "PermanentResidentCard"],
  "issuer": "did:example:489398593",
  "identifier": 83627465,
  "name": "Permanent Resident Card",
  "description": "Government of Example Permanent Resident Card.",
  "issuanceDate": "2019-12-03T12:19:52Z",
  "expirationDate": "2029-12-03T12:19:52Z",
  "credentialSubject": [
    {
      "id": "did:example:b34ca6cd37bbf23",
      "type": ["PermanentResident", "Person"],
      "givenName": "JOHN",
      "familyName": "SMITH",
      "gender": "Male",
      "image": "data:image/png;base64,iVBORw0KGgokJggg==",
      "residentSince": "2015-01-01",
      "lprCategory": "C09",
      "lprNumber": "999-999-999",
      "commuterClassification": "C1",
      "birthCountry": "Bahamas",
      "birthDate": "1958-07-17"
    },
    {
      "id": "did:example:b34ca6cd37bbf24",
      "type": ["PermanentResident", "Person"],
      "givenName": "JOHN",
      "familyName": "SMITH",
      "gender": "Male",
      "image": "data:image/png;base64,iVBORw0KGgokJggg==",
      "residentSince": "2015-01-01",
      "lprCategory": "C09",
      "lprNumber": "999-999-999",
      "commuterClassification": "C1",
      "birthCountry": "Bahamas",
      "birthDate": "1958-07-18"
    }
  ]
}`

var testDocumentIPFSURLMaps = map[string]string{
	"https://www.w3.org/2018/credentials/v1":                              "testdata/httpresp/credentials-v1.jsonld",
	"https://schema.iden3.io/core/jsonld/iden3proofs.jsonld":              "testdata/httpresp/iden3proofs.json-ld",
	"https://ipfs.io/ipfs/QmeMevwUeD7o6hjfmdaeFD1q4L84hSDiRjeXZLi1bZK1My": "testdata/ipfs/testNewType.jsonld",
}

const testDocumentIPFS = `{
  "id": "https://dev.polygonid.me/api/v1/identities/did:polygonid:polygon:mumbai:2qLPqvayNQz9TA2r5VPxUugoF18teGU583zJ859wfy/claims/eca334b0-0e7d-11ee-889c-0242ac1d0006",
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://schema.iden3.io/core/jsonld/iden3proofs.jsonld",
    "ipfs://QmeMevwUeD7o6hjfmdaeFD1q4L84hSDiRjeXZLi1bZK1My"
  ],
  "type": [
    "VerifiableCredential",
    "testNewType"
  ],
  "expirationDate": "2030-01-01T00:00:00Z",
  "issuanceDate": "2023-06-19T08:47:29.888363862Z",
  "credentialSubject": {
    "id": "did:polygonid:polygon:mumbai:2qFTXJyiehHC19zLffRc9DYT88LQRViufWJzFSHCqL",
    "testNewTypeInt": 1,
    "type": "testNewType"
  },
  "credentialStatus": {
    "id": "https://dev.polygonid.me/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qLPqvayNQz9TA2r5VPxUugoF18teGU583zJ859wfy/claims/revocation/status/162771772",
    "revocationNonce": 162771772,
    "type": "SparseMerkleTreeProof"
  },
  "issuer": "did:polygonid:polygon:mumbai:2qLPqvayNQz9TA2r5VPxUugoF18teGU583zJ859wfy",
  "credentialSchema": {
    "id": "ipfs://QmQVeb5dkz5ekDqBrYVVxBFQZoCbzamnmMUn9B8twCEgDL",
    "type": "JsonSchemaValidator2018"
  },
  "proof": [
    {
      "type": "BJJSignature2021",
      "issuerData": {
        "id": "did:polygonid:polygon:mumbai:2qLPqvayNQz9TA2r5VPxUugoF18teGU583zJ859wfy",
        "state": {
          "txId": "0xde8c8e234e9e4c159b9ce6361234c15eaaa123bddf15f395489a75e634e11182",
          "blockTimestamp": 1683792462,
          "blockNumber": 35452981,
          "rootOfRoots": "03beaa14074a91698084d2dc077067babb8334584a7d73a047e6b238341b581d",
          "claimsTreeRoot": "a5faef8b1fc67f65c55ad667919e51abfed008ca97475c41b26a5e70fd4c4a0a",
          "revocationTreeRoot": "0000000000000000000000000000000000000000000000000000000000000000",
          "value": "5ab768f8f2ec3f94e6830908fbf428ca3386ff87a5e704fcd1f11cae3420611f"
        },
        "authCoreClaim": "cca3371a6cb1b715004407e325bd993c080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e3b9e422feb1dcf83882b33bddf3c9a64d300e2280e9c286bb75839c824ace27c5560b8ca92be27698a14f6970c32731e73768d74fe83d0fd4f16f14b4402d242dd87d9900000000281cdcdf0200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "mtp": {
          "existence": true,
          "siblings": [
            "16600125203338042323361216512603158366636445287571403125891881295088432028008",
            "11315256355804790111057838658876672619892914293003422319088357823149445991751",
            "5953630948937947438067785504646477838099205855387889079750411149043045455341",
            "7144700925452824210038939338852356191428773494854012082867969138805603048585",
            "3921545027306074721354497759643961758048633515411954472382458013486548057049",
            "0",
            "0",
            "5436254548464410857916946211162171910597645182542037135954554779197265908702"
          ]
        },
        "credentialStatus": {
          "id": "https://dev.polygonid.me/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qLPqvayNQz9TA2r5VPxUugoF18teGU583zJ859wfy/claims/revocation/status/2575161389",
          "revocationNonce": 2575161389,
          "type": "SparseMerkleTreeProof"
        }
      },
      "coreClaim": "d7939e871529d085f1c549ab8e3484642a000000000000000000000000000000021241e014bc0bed916380369c66daf6a49a2efaafe19b9eead97ecd45fb0f007a4a3b209875d293677af876eb5a00b97739bcff3aef28d677654a4216fe142100000000000000000000000000000000000000000000000000000000000000003cb3b3090000000080d8db700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      "signature": "b25559a5b4f56e4279f318440e3f57173046abf46970a34725cc293146cd07af5a1554462d8254f11bea18c0e32969b8e5bb740a74e0f79cf81639c2249b4103"
    },
    {
      "type": "Iden3SparseMerkleTreeProof",
      "issuerData": {
        "id": "did:polygonid:polygon:mumbai:2qLPqvayNQz9TA2r5VPxUugoF18teGU583zJ859wfy",
        "state": {
          "txId": "0xd7acd97658a9fd46fcecc297a2658e87484c4fb158b5cc751fa55cc66a528901",
          "blockTimestamp": 1687164493,
          "blockNumber": 37031106,
          "rootOfRoots": "013157d23e45439d797cf21eff7cce75a62c571eeebbd4bb3fc0f82b938e2725",
          "claimsTreeRoot": "db2b0678c8d26177a6c7b316cac669f1d37baf6e69a9a8f45dd2b0127008a50c",
          "revocationTreeRoot": "2f81358078a2ea3874ce6000994fc57d399b57d2d2239fc0d40e7112409af804",
          "value": "4d997e8bf918046a338da7d3a60fc1a66b9b549718b8391071ca2eef8951492a"
        }
      },
      "coreClaim": "d7939e871529d085f1c549ab8e3484642a000000000000000000000000000000021241e014bc0bed916380369c66daf6a49a2efaafe19b9eead97ecd45fb0f007a4a3b209875d293677af876eb5a00b97739bcff3aef28d677654a4216fe142100000000000000000000000000000000000000000000000000000000000000003cb3b3090000000080d8db700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      "mtp": {
        "existence": true,
        "siblings": [
          "7014863375885756478216431089540562731662914991320699716584671851123060599668",
          "21315600889769805398676045356078521059928852692746112705474647520974404948890",
          "21548560938430009683383944561421125979714483097439757511725983865213908705359",
          "20098927269510769492310533561375018705245216008792620555365069905774375917381",
          "7203728335210032481762971413039087279239292151184438299705033616348328560570",
          "0",
          "0",
          "0",
          "0",
          "6742687216537986078187329258797021007707864223416791051080996892176890387669"
        ]
      }
    }
  ]
}`

func getDataset(t testing.TB, document string) *ld.RDFDataset {
	var obj map[string]interface{}
	err := json.Unmarshal([]byte(document), &obj)
	if err != nil {
		panic(err)
	}

	proc := ld.NewJsonLdProcessor()
	options := ld.NewJsonLdOptions("")
	options.Algorithm = "URDNA2015"

	out4, err := proc.Normalize(obj, options)
	require.NoError(t, err)

	out5, ok := out4.(*ld.RDFDataset)
	require.True(t, ok, "%[1]T\n%[1]v", out4)

	return out5
}

func mkPath(parts ...interface{}) Path {
	p, err := NewPath(parts...)
	if err != nil {
		panic(err)
	}
	return p
}

func TestEntriesFromRDF_multigraph(t *testing.T) {
	defer tst.MockHTTPClient(t, multigraphDoc2URLMaps,
		tst.IgnoreUntouchedURLs())()
	dataset := getDataset(t, multigraphDoc2)

	entries, err := EntriesFromRDF(dataset)
	require.NoError(t, err)
	// To generate wantEntries, uncomment the following line
	// printEntriesRepresentation(entries)

	wantEntries := []RDFEntry{
		{
			key:   mkPath("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"),
			value: "https://www.w3.org/2018/credentials#VerifiablePresentation",
		},
		{
			key:   mkPath("https://www.w3.org/2018/credentials#holder", 0),
			value: "http://example.com/holder1",
		},
		{
			key:   mkPath("https://www.w3.org/2018/credentials#holder", 1),
			value: "http://example.com/holder2",
		},
		{
			key: mkPath("https://www.w3.org/2018/credentials#verifiableCredential",
				0, "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"),
			value: "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld#Iden3SparseMerkleTreeProof",
		},
		{
			key: mkPath("https://www.w3.org/2018/credentials#verifiableCredential",
				0,
				"https://github.com/iden3/claim-schema-vocab/blob/main/proofs/Iden3SparseMerkleTreeProof-v2.md#issuerData",
				"https://github.com/iden3/claim-schema-vocab/blob/main/proofs/Iden3SparseMerkleTreeProof-v2.md#state",
				"https://github.com/iden3/claim-schema-vocab/blob/main/proofs/Iden3SparseMerkleTreeProof-v2.md#blockTimestamp"),

			value: big.NewInt(123),

			datatype: "http://www.w3.org/2001/XMLSchema#integer",
		},
		{
			key: mkPath("https://www.w3.org/2018/credentials#verifiableCredential",
				1, "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"),
			value: "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld#KYCAgeCredential",
		},
		{
			key: mkPath("https://www.w3.org/2018/credentials#verifiableCredential",
				1,
				"https://github.com/iden3/claim-schema-vocab/blob/main/credentials/kyc.md#birthday"),

			value: big.NewInt(19960424),

			datatype: "http://www.w3.org/2001/XMLSchema#integer",
		},
	}

	require.Equal(t, wantEntries, entries)
}

func TestEntriesFromRDF(t *testing.T) {
	defer tst.MockHTTPClient(t, testDocumentURLMaps)()

	dataset := getDataset(t, testDocument)

	entries, err := EntriesFromRDF(dataset)
	require.NoError(t, err)

	wantEntries := []RDFEntry{
		{
			key: mkPath(
				"https://www.w3.org/2018/credentials#credentialSubject", 0,
				"http://schema.org/birthDate"),
			value:    time.Date(1958, 7, 17, 0, 0, 0, 0, time.UTC),
			datatype: "http://www.w3.org/2001/XMLSchema#dateTime",
		},
		{
			key: mkPath(
				"https://www.w3.org/2018/credentials#credentialSubject", 0,
				"http://schema.org/familyName"),
			value:    "SMITH",
			datatype: "http://www.w3.org/2001/XMLSchema#string",
		},
		{
			key: mkPath(
				"https://www.w3.org/2018/credentials#credentialSubject", 0,
				"http://schema.org/gender"),
			value:    "Male",
			datatype: "http://www.w3.org/2001/XMLSchema#string",
		},
		{
			key: mkPath(
				"https://www.w3.org/2018/credentials#credentialSubject", 0,
				"http://schema.org/givenName"),
			value:    "JOHN",
			datatype: "http://www.w3.org/2001/XMLSchema#string",
		},
		{
			key: mkPath(
				"https://www.w3.org/2018/credentials#credentialSubject", 0,
				"http://schema.org/image"),
			value:    "data:image/png;base64,iVBORw0KGgokJggg==",
			datatype: "",
		},
		{
			key: mkPath(
				"https://www.w3.org/2018/credentials#credentialSubject", 0,
				"http://www.w3.org/1999/02/22-rdf-syntax-ns#type", 0),
			value:    "http://schema.org/Person",
			datatype: "",
		},
		{
			key: mkPath(
				"https://www.w3.org/2018/credentials#credentialSubject", 0,
				"http://www.w3.org/1999/02/22-rdf-syntax-ns#type", 1),
			value:    "https://w3id.org/citizenship#PermanentResident",
			datatype: "",
		},
		{
			key: mkPath(
				"https://www.w3.org/2018/credentials#credentialSubject", 0,
				"https://w3id.org/citizenship#birthCountry"),
			value:    "Bahamas",
			datatype: "http://www.w3.org/2001/XMLSchema#string",
		},
		{
			key: mkPath(
				"https://www.w3.org/2018/credentials#credentialSubject", 0,
				"https://w3id.org/citizenship#commuterClassification"),
			value:    "C1",
			datatype: "http://www.w3.org/2001/XMLSchema#string",
		},
		{
			key: mkPath(
				"https://www.w3.org/2018/credentials#credentialSubject", 0,
				"https://w3id.org/citizenship#lprCategory"),
			value:    "C09",
			datatype: "http://www.w3.org/2001/XMLSchema#string",
		},
		{
			key: mkPath(
				"https://www.w3.org/2018/credentials#credentialSubject", 0,
				"https://w3id.org/citizenship#lprNumber"),
			value:    "999-999-999",
			datatype: "http://www.w3.org/2001/XMLSchema#string",
		},
		{
			key: mkPath(
				"https://www.w3.org/2018/credentials#credentialSubject", 0,
				"https://w3id.org/citizenship#residentSince"),
			value:    time.Date(2015, 1, 1, 0, 0, 0, 0, time.UTC),
			datatype: "http://www.w3.org/2001/XMLSchema#dateTime",
		},
		{
			key: mkPath(
				"https://www.w3.org/2018/credentials#credentialSubject", 1,
				"http://schema.org/birthDate"),
			value:    time.Date(1958, 7, 18, 0, 0, 0, 0, time.UTC),
			datatype: "http://www.w3.org/2001/XMLSchema#dateTime",
		},
		{
			key: mkPath(
				"https://www.w3.org/2018/credentials#credentialSubject", 1,
				"http://schema.org/familyName"),
			value:    "SMITH",
			datatype: "http://www.w3.org/2001/XMLSchema#string",
		},
		{
			key: mkPath(
				"https://www.w3.org/2018/credentials#credentialSubject", 1,
				"http://schema.org/gender"),
			value:    "Male",
			datatype: "http://www.w3.org/2001/XMLSchema#string",
		},
		{
			key: mkPath(
				"https://www.w3.org/2018/credentials#credentialSubject", 1,
				"http://schema.org/givenName"),
			value:    "JOHN",
			datatype: "http://www.w3.org/2001/XMLSchema#string",
		},
		{
			key: mkPath(
				"https://www.w3.org/2018/credentials#credentialSubject", 1,
				"http://schema.org/image"),
			value:    "data:image/png;base64,iVBORw0KGgokJggg==",
			datatype: "",
		},
		{
			key: mkPath(
				"https://www.w3.org/2018/credentials#credentialSubject", 1,
				"http://www.w3.org/1999/02/22-rdf-syntax-ns#type", 0),
			value:    "http://schema.org/Person",
			datatype: "",
		},
		{
			key: mkPath(
				"https://www.w3.org/2018/credentials#credentialSubject", 1,
				"http://www.w3.org/1999/02/22-rdf-syntax-ns#type", 1),
			value:    "https://w3id.org/citizenship#PermanentResident",
			datatype: "",
		},
		{
			key: mkPath(
				"https://www.w3.org/2018/credentials#credentialSubject", 1,
				"https://w3id.org/citizenship#birthCountry"),
			value:    "Bahamas",
			datatype: "http://www.w3.org/2001/XMLSchema#string",
		},
		{
			key: mkPath(
				"https://www.w3.org/2018/credentials#credentialSubject", 1,
				"https://w3id.org/citizenship#commuterClassification"),
			value:    "C1",
			datatype: "http://www.w3.org/2001/XMLSchema#string",
		},
		{
			key: mkPath(
				"https://www.w3.org/2018/credentials#credentialSubject", 1,
				"https://w3id.org/citizenship#lprCategory"),
			value:    "C09",
			datatype: "http://www.w3.org/2001/XMLSchema#string",
		},
		{
			key: mkPath(
				"https://www.w3.org/2018/credentials#credentialSubject", 1,
				"https://w3id.org/citizenship#lprNumber"),
			value:    "999-999-999",
			datatype: "http://www.w3.org/2001/XMLSchema#string",
		},
		{
			key: mkPath(
				"https://www.w3.org/2018/credentials#credentialSubject", 1,
				"https://w3id.org/citizenship#residentSince"),
			value:    time.Date(2015, 1, 1, 0, 0, 0, 0, time.UTC),
			datatype: "http://www.w3.org/2001/XMLSchema#dateTime",
		},
		{
			key:      mkPath("http://schema.org/description"),
			value:    "Government of Example Permanent Resident Card.",
			datatype: "http://www.w3.org/2001/XMLSchema#string",
		},
		{
			key: mkPath("http://schema.org/identifier"),

			value: big.NewInt(83627465),

			datatype: "http://www.w3.org/2001/XMLSchema#integer",
		},
		{
			key:      mkPath("http://schema.org/name"),
			value:    "Permanent Resident Card",
			datatype: "http://www.w3.org/2001/XMLSchema#string",
		},
		{
			key: mkPath("http://www.w3.org/1999/02/22-rdf-syntax-ns#type",
				0),
			value:    "https://w3id.org/citizenship#PermanentResidentCard",
			datatype: "",
		},
		{
			key: mkPath("http://www.w3.org/1999/02/22-rdf-syntax-ns#type",
				1),
			value:    "https://www.w3.org/2018/credentials#VerifiableCredential",
			datatype: "",
		},
		{
			key: mkPath("https://www.w3.org/2018/credentials#credentialSubject",
				0),
			value:    "did:example:b34ca6cd37bbf23",
			datatype: "",
		},
		{
			key: mkPath("https://www.w3.org/2018/credentials#credentialSubject",
				1),
			value:    "did:example:b34ca6cd37bbf24",
			datatype: "",
		},
		{
			key: mkPath("https://www.w3.org/2018/credentials#expirationDate"),
			//value: "2029-12-03T12:19:52Z",
			value:    time.Date(2029, 12, 3, 12, 19, 52, 0, time.UTC),
			datatype: "http://www.w3.org/2001/XMLSchema#dateTime",
		},
		{
			key: mkPath("https://www.w3.org/2018/credentials#issuanceDate"),
			//value: "2019-12-03T12:19:52Z",
			value:    time.Date(2019, 12, 3, 12, 19, 52, 0, time.UTC),
			datatype: "http://www.w3.org/2001/XMLSchema#dateTime",
		},
		{
			key:      mkPath("https://www.w3.org/2018/credentials#issuer"),
			value:    "did:example:489398593",
			datatype: "",
		},
	}
	require.Equal(t, wantEntries, entries)
}

func TestProof(t *testing.T) {
	defer tst.MockHTTPClient(t, testDocumentURLMaps)()
	dataset := getDataset(t, testDocument)

	entries, err := EntriesFromRDF(dataset)
	require.NoError(t, err)

	ctx := context.Background()

	mt, err := merkletree.NewMerkleTree(ctx, memory.NewMemoryStorage(), 40)
	require.NoError(t, err)

	err = AddEntriesToMerkleTree(ctx, mt, entries)
	require.NoError(t, err)

	// [https://www.w3.org/2018/credentials#credentialSubject 1 http://schema.org/birthDate] => 1958-07-18
	path, err := NewPath(
		"https://www.w3.org/2018/credentials#credentialSubject", 1,
		"http://schema.org/birthDate")
	require.NoError(t, err)

	birthDate := time.Date(1958, 7, 18, 0, 0, 0, 0, time.UTC)
	entry, err := NewRDFEntry(path, birthDate)
	require.NoError(t, err)

	key, val, err := entry.KeyValueMtEntries()
	require.NoError(t, err)

	p, _, err := mt.GenerateProof(ctx, key, nil)
	require.NoError(t, err)

	ok := merkletree.VerifyProof(mt.Root(), p, key, val)
	require.True(t, ok)
}

func TestProofInteger(t *testing.T) {
	defer tst.MockHTTPClient(t, testDocumentURLMaps)()
	dataset := getDataset(t, testDocument)

	entries, err := EntriesFromRDF(dataset)
	require.NoError(t, err)

	ctx := context.Background()

	mt, err := merkletree.NewMerkleTree(ctx, memory.NewMemoryStorage(), 40)
	require.NoError(t, err)

	err = AddEntriesToMerkleTree(ctx, mt, entries)
	require.NoError(t, err)

	path, err := NewPath("http://schema.org/identifier")
	require.NoError(t, err)

	entry, err := NewRDFEntry(path, 83627465)
	require.NoError(t, err)

	key, val, err := entry.KeyValueMtEntries()
	require.NoError(t, err)

	p, _, err := mt.GenerateProof(ctx, key, nil)
	require.NoError(t, err)

	ok := merkletree.VerifyProof(mt.Root(), p, key, val)
	require.True(t, ok)
}

func TestMerklizer_Proof(t *testing.T) {
	defer tst.MockHTTPClient(t, testDocumentURLMaps, tst.IgnoreUntouchedURLs())()
	ctx := context.Background()
	mz, err := MerklizeJSONLD(ctx, strings.NewReader(testDocument))
	require.NoError(t, err)

	t.Run("test with path as Path", func(t *testing.T) {
		// [https://www.w3.org/2018/credentials#credentialSubject 1 http://schema.org/birthDate] => 1958-07-18
		path, err := NewPath(
			"https://www.w3.org/2018/credentials#credentialSubject", 1,
			"http://schema.org/birthDate")
		require.NoError(t, err)

		p, value, err := mz.Proof(ctx, path)
		require.NoError(t, err)

		pathMtEntry, err := path.MtEntry()
		require.NoError(t, err)

		require.True(t, value.IsTime())
		valueDateType, err := value.AsTime()
		require.NoError(t, err)

		birthDate := time.Date(1958, 7, 18, 0, 0, 0, 0, time.UTC)
		require.True(t, birthDate.Equal(valueDateType))

		valueMtEntry, err := value.MtEntry()
		require.NoError(t, err)

		ok := merkletree.VerifyProof(mz.Root(), p, pathMtEntry, valueMtEntry)
		require.True(t, ok)
	})

	t.Run("test with path as shortcut string", func(t *testing.T) {
		path, err := mz.ResolveDocPath("credentialSubject.1.birthCountry")
		require.NoError(t, err)

		p, value, err := mz.Proof(ctx, path)
		require.NoError(t, err)

		require.True(t, value.IsString())
		valueStr, err := value.AsString()
		require.NoError(t, err)
		require.Equal(t, "Bahamas", valueStr)
		valueMtEntry, err := value.MtEntry()
		require.NoError(t, err)

		pathMtEntry, err := path.MtEntry()
		require.NoError(t, err)

		ok := merkletree.VerifyProof(mz.Root(), p, pathMtEntry, valueMtEntry)
		require.True(t, ok)
	})

	t.Run("test RawValue", func(t *testing.T) {
		// [https://www.w3.org/2018/credentials#credentialSubject 1 http://schema.org/birthDate] => 1958-07-18
		path, err := NewPath(
			"https://www.w3.org/2018/credentials#credentialSubject", 1,
			"http://schema.org/birthDate")
		require.NoError(t, err)

		// Check RawValue with index in path
		rv, err := mz.RawValue(path)
		require.NoError(t, err)
		require.Equal(t, "1958-07-18", rv)

		// Check RawValue as a number in json
		identifierPath, err := NewPath("http://schema.org/identifier")
		require.NoError(t, err)
		rv, err = mz.RawValue(identifierPath)
		require.NoError(t, err)
		require.Equal(t, float64(83627465), rv)

		// Check RawValue with wrong path (expected array, but got object)
		wrongPath, err := NewPath("http://schema.org/identifier", 1)
		require.NoError(t, err)
		_, err = mz.RawValue(wrongPath)
		require.EqualError(t, err,
			"expected array at 'http://schema.org/identifier / [1]'")

		wrongPath, err = NewPath(
			"https://www.w3.org/2018/credentials#credentialSubject", 5,
			"http://schema.org/birthDate")
		require.NoError(t, err)
		_, err = mz.RawValue(wrongPath)
		require.EqualError(t, err,
			"index is out of range at 'https://www.w3.org/2018/credentials#credentialSubject / [5]'")

		wrongPath, err = NewPath("bla-bla", 5)
		require.NoError(t, err)
		_, err = mz.RawValue(wrongPath)
		require.EqualError(t, err, "value not found at 'bla-bla'")

		wrongPath, err = NewPath(
			"https://www.w3.org/2018/credentials#credentialSubject", "bla-bla")
		require.NoError(t, err)
		_, err = mz.RawValue(wrongPath)
		require.EqualError(t, err,
			"expected object at 'https://www.w3.org/2018/credentials#credentialSubject / bla-bla'")
	})

	mzRoot := mz.Root()
	require.Equal(t,
		"d001de1d1b74d3b24b394566511da50df18532264c473845ea51e915a588b02a",
		mzRoot.Hex())
}

//nolint:deadcode,unused // use for debugging
func logDataset(in *ld.RDFDataset) {
	fmt.Printf("Log dataset of %v keys\n", len(in.Graphs))
	for s, gs := range in.Graphs {
		fmt.Printf("Key %v has %v entries\n", s, len(gs))
		for i, g := range gs {
			subject := "nil"
			if g.Subject != nil {
				subject = g.Subject.GetValue()
			}
			predicate := "nil"
			if g.Predicate != nil {
				predicate = g.Predicate.GetValue()
			}
			object := "nil"
			var ol2 string
			ol, olOK := g.Object.(*ld.Literal)
			if olOK {
				ol2 = ol.Datatype
			}

			if g.Object != nil {
				object = g.Object.GetValue()
			}
			graph := "nil"
			if g.Graph != nil {
				graph = g.Graph.GetValue()
			}
			fmt.Printf(`Entry %v:
	Subject [%T]: %v
	Predicate [%T]: %v
	Object [%T]: %v %v
	Graph [%T]: %v
`, i,
				g.Subject, subject,
				g.Predicate, predicate,
				g.Object, object, ol2,
				g.Graph, graph)
		}
	}
}

//nolint:deadcode,unused //reason: used in debugging
func fmtPath(p Path) string {
	var parts []string
	for _, pi := range p.parts {
		switch v := pi.(type) {
		case string:
			parts = append(parts, v)
		case int:
			parts = append(parts, strconv.Itoa(v))
		default:
			panic("not string or int")
		}
	}
	return strings.Join(parts, " :: ")
}

func TestPathFromContext(t *testing.T) {
	// this file downloaded from here: https://www.w3.org/2018/credentials/v1
	ctxBytes, err := os.ReadFile("testdata/custom_schema.json")
	require.NoError(t, err)

	in := "VerifiableCredential.credentialSchema.JsonSchemaValidator2018"
	result, err := NewPathFromContext(ctxBytes, in)
	require.NoError(t, err)

	want, err := NewPath(
		"https://www.w3.org/2018/credentials#VerifiableCredential",
		"https://www.w3.org/2018/credentials#credentialSchema",
		"https://www.w3.org/2018/credentials#JsonSchemaValidator2018")
	require.NoError(t, err)

	require.Equal(t, want, result)
}

func TestFieldPathFromContext(t *testing.T) {
	ctxBytes, err := os.ReadFile("testdata/kyc_schema.json-ld")
	require.NoError(t, err)

	typ := "KYCAgeCredential"
	fieldPath := "birthday"
	result, err := NewFieldPathFromContext(ctxBytes, typ, fieldPath)
	require.NoError(t, err)

	want, err := NewPath(
		"https://github.com/iden3/claim-schema-vocab/blob/main/credentials/kyc.md#birthday")
	require.NoError(t, err)

	require.Equal(t, want, result)
}

func TestPathFromDocument(t *testing.T) {
	t.Run("path with index array", func(t *testing.T) {
		in := "credentialSubject.1.birthDate"
		result, err := NewPathFromDocument([]byte(testDocument), in)
		require.NoError(t, err)

		want, err := NewPath(
			"https://www.w3.org/2018/credentials#credentialSubject",
			1,
			"http://schema.org/birthDate")
		require.NoError(t, err)

		require.Equal(t, want, result)
	})

	t.Run("path to nested field", func(t *testing.T) {
		path, err := NewPathFromDocument([]byte(nestedFieldDocument),
			"objectField.customNestedField")
		require.NoError(t, err)

		want, err := NewPath(
			"urn:uuid:87caf7a2-fee3-11ed-be56-0242ac120001#objectField",
			"urn:uuid:87caf7a2-fee3-11ed-be56-0242ac120001#customNestedField")
		require.NoError(t, err)
		require.Equal(t, want, path)
	})
}

func TestMkValueInt(t *testing.T) {
	testCases := []struct {
		in   int64
		want string
	}{
		{
			in:   -1,
			want: "21888242871839275222246405745257275088548364400416034343698204186575808495616",
		},
		{
			in:   -2,
			want: "21888242871839275222246405745257275088548364400416034343698204186575808495615",
		},
		{
			in:   math.MinInt64,
			want: "21888242871839275222246405745257275088548364400416034343688980814538953719809",
		},
	}
	for i := range testCases {
		tc := testCases[i]
		t.Run(fmt.Sprintf("#%v", i+1), func(t *testing.T) {
			v, err := mkValueInt(defaultHasher, tc.in)
			require.NoError(t, err)
			require.Equal(t, tc.want, v.Text(10))
		})
	}

	t.Run("int value", func(t *testing.T) {
		v, err := mkValueInt(defaultHasher, int(math.MinInt64))
		require.NoError(t, err)
		require.Equal(t,
			"21888242871839275222246405745257275088548364400416034343688980814538953719809",
			v.Text(10))
	})
}

func TestValue(t *testing.T) {
	// bool
	v, err := NewValue(defaultHasher, true)
	require.NoError(t, err)
	require.False(t, v.IsString())
	require.True(t, v.IsBool())
	require.False(t, v.IsInt64())
	require.False(t, v.IsTime())
	b, err := v.AsBool()
	require.NoError(t, err)
	require.True(t, b)
	_, err = v.AsString()
	require.ErrorIs(t, err, ErrIncorrectType)

	// string
	s, err := NewValue(defaultHasher, "str")
	require.NoError(t, err)
	require.True(t, s.IsString())
	require.False(t, s.IsBool())
	require.False(t, s.IsInt64())
	require.False(t, s.IsTime())
	s2, err := s.AsString()
	require.NoError(t, err)
	require.Equal(t, "str", s2)
	_, err = s.AsInt64()
	require.ErrorIs(t, err, ErrIncorrectType)

	// string
	i, err := NewValue(defaultHasher, int64(3))
	require.NoError(t, err)
	require.False(t, i.IsString())
	require.False(t, i.IsBool())
	require.True(t, i.IsInt64())
	require.False(t, i.IsTime())
	i2, err := i.AsInt64()
	require.NoError(t, err)
	require.Equal(t, int64(3), i2)
	_, err = i.AsTime()
	require.ErrorIs(t, err, ErrIncorrectType)

	// time.Time
	tm := time.Date(2022, 10, 20, 3, 4, 5, 6, time.UTC)
	tm2, err := NewValue(defaultHasher, tm)
	require.NoError(t, err)
	require.False(t, tm2.IsString())
	require.False(t, tm2.IsBool())
	require.False(t, tm2.IsInt64())
	require.True(t, tm2.IsTime())
	tm3, err := tm2.AsTime()
	require.NoError(t, err)
	require.True(t, tm3.Equal(tm))
	_, err = tm2.AsBool()
	require.ErrorIs(t, err, ErrIncorrectType)
}

var doc1URLMaps = map[string]string{
	"https://www.w3.org/2018/credentials/v1": "testdata/httpresp/credentials-v1.jsonld",
	"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld": "testdata/httpresp/iden3credential-v2.json-ld",
	"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":             "testdata/httpresp/kyc-v3.json-ld",
}

// multiple types within another type
var doc1 = `
{
    "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld",
        "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld"
    ],
    "@type": [
        "VerifiableCredential",
        "KYCAgeCredential"
    ],
    "id": "http://myid.com",
    "expirationDate": "2261-03-21T21:14:48+02:00",
    "credentialSubject": {
        "type": "KYCAgeCredential",
        "id": "did:iden3:polygon:mumbai:wyFiV4w71QgWPn6bYLsZoysFay66gKtVa9kfu6yMZ",
        "documentType": 1,
        "birthday": 19960424
    },
    "credentialStatus": {
        "type": "SparseMerkleTreeProof",
        "id": "http://localhost:8001/api/v1/identities/1195DjqzhZ9zpHbezahSevDMcxN41vs3Y6gb4noRW/claims/revocation/status/127366661"
    },
    "credentialSchema": {
        "type": "JsonSchemaValidator2018",
        "id": "http://json1.com"
    }
}`

func TestExistenceProof(t *testing.T) {
	defer tst.MockHTTPClient(t, doc1URLMaps)()
	ctx := context.Background()
	mz, err := MerklizeJSONLD(ctx, strings.NewReader(doc1), WithIPFSGateway("https://ipfs.io"))
	require.NoError(t, err)
	path, err := mz.ResolveDocPath("credentialSubject.birthday")
	require.NoError(t, err)

	wantPath, err := NewPath(
		"https://www.w3.org/2018/credentials#credentialSubject",
		"https://github.com/iden3/claim-schema-vocab/blob/main/credentials/kyc.md#birthday")
	require.NoError(t, err)
	require.Equal(t, wantPath, path)

	p, v, err := mz.Proof(ctx, path)
	require.NoError(t, err)

	require.True(t, p.Existence)
	i, err := v.AsBigInt()
	require.NoError(t, err)
	require.Equal(t, 0, i.Cmp(big.NewInt(19960424)), i)
}

func TestExistenceProofIPFS(t *testing.T) {
	defer tst.MockHTTPClient(t, testDocumentIPFSURLMaps)()
	ctx := context.Background()
	mz, err := MerklizeJSONLD(ctx, strings.NewReader(testDocumentIPFS),
		WithIPFSGateway("https://ipfs.io"))
	require.NoError(t, err)
	path, err := mz.ResolveDocPath("credentialSubject.testNewTypeInt")
	require.NoError(t, err)

	wantPath, err := NewPath(
		"https://www.w3.org/2018/credentials#credentialSubject",
		"urn:uuid:0a8092e3-7100-4068-ba67-fae502cc6e7b#testNewTypeInt")
	require.NoError(t, err)
	require.Equal(t, wantPath, path)

	p, v, err := mz.Proof(ctx, path)
	require.NoError(t, err)

	require.True(t, p.Existence)
	i, err := v.AsBigInt()
	require.NoError(t, err)
	require.Equal(t, 0, big.NewInt(1).Cmp(i))
}

func findQuadByObject(t testing.TB, ds *ld.RDFDataset, value any) *ld.Quad {
	for _, quads := range ds.Graphs {
		for _, quad := range quads {
			if reflect.DeepEqual(value, quad.Object) {
				return quad
			}
		}
	}

	t.Fatal("quad not found")
	return nil
}

func findQuadByIdx(t testing.TB, ds *ld.RDFDataset, idx datasetIdx) *ld.Quad {
	quads, ok := ds.Graphs[idx.graph]
	if !ok {
		t.Fatal("graph not found")
	}
	if len(quads) < idx.idx+1 {
		t.Fatal("quad not found")
	}
	return quads[idx.idx]
}

var multigraphDoc2URLMaps = map[string]string{
	"https://www.w3.org/2018/credentials/v1":                                                                     "testdata/httpresp/credentials-v1.jsonld",
	"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":             "testdata/httpresp/kyc-v3.json-ld",
	"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld": "testdata/httpresp/iden3credential-v2.json-ld",
}

const multigraphDoc2 = `{
  "@context":[
    "https://www.w3.org/2018/credentials/v1",
    "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
    "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld"
  ],
  "@type":"VerifiablePresentation",
  "holder": ["http://example.com/holder1", "http://example.com/holder2"],
  "verifiableCredential":[
    {
      "@id": "http://example.com/vc1",
      "@type":"KYCAgeCredential",
      "birthday":19960424
    },
    {
      "@id": "http://example.com/vc3",
      "@type": "Iden3SparseMerkleTreeProof",
      "issuerData": {
        "state": {
          "blockTimestamp": 123
        }
      }
    }
  ]
}`

func Test_findParentInsideGraph_And_findGraphParent(t *testing.T) {
	defer tst.MockHTTPClient(t, multigraphDoc2URLMaps)()
	ds := getDataset(t, multigraphDoc2)
	q := findQuadByObject(t, ds, &ld.Literal{
		Value:    "123",
		Datatype: ld.XSDInteger,
		Language: "",
	})
	idx, err := findParentInsideGraph(ds, q)
	require.NoError(t, err)
	q = findQuadByIdx(t, ds, idx)
	assert.Equal(t,
		&ld.IRI{Value: "https://github.com/iden3/claim-schema-vocab/blob/main/proofs/Iden3SparseMerkleTreeProof-v2.md#state"},
		q.Predicate)

	idx, err = findParentInsideGraph(ds, q)
	require.NoError(t, err)
	q = findQuadByIdx(t, ds, idx)
	assert.Equal(t,
		&ld.IRI{Value: "http://example.com/vc3"},
		q.Subject)
	assert.Equal(t,
		&ld.IRI{Value: "https://github.com/iden3/claim-schema-vocab/blob/main/proofs/Iden3SparseMerkleTreeProof-v2.md#issuerData"},
		q.Predicate)

	_, err = findParentInsideGraph(ds, q)
	require.ErrorIs(t, err, errParentNotFound)

	idx, err = findGraphParent(ds, q)
	require.NoError(t, err)
	q = findQuadByIdx(t, ds, idx)
	assert.Equal(t,
		&ld.IRI{Value: "https://www.w3.org/2018/credentials#verifiableCredential"},
		q.Predicate)

	_, err = findParentInsideGraph(ds, q)
	require.ErrorIs(t, err, errParentNotFound)
}

func Test_findParent(t *testing.T) {
	defer tst.MockHTTPClient(t, multigraphDoc2URLMaps)()
	ds := getDataset(t, multigraphDoc2)
	q := findQuadByObject(t, ds, &ld.Literal{
		Value:    "123",
		Datatype: ld.XSDInteger,
		Language: "",
	})
	idx, err := findParent(ds, q)
	require.NoError(t, err)
	q = findQuadByIdx(t, ds, idx)
	assert.Equal(t,
		&ld.IRI{Value: "https://github.com/iden3/claim-schema-vocab/blob/main/proofs/Iden3SparseMerkleTreeProof-v2.md#state"},
		q.Predicate)

	idx, err = findParent(ds, q)
	require.NoError(t, err)
	q = findQuadByIdx(t, ds, idx)
	assert.Equal(t,
		&ld.IRI{Value: "http://example.com/vc3"},
		q.Subject)
	assert.Equal(t,
		&ld.IRI{Value: "https://github.com/iden3/claim-schema-vocab/blob/main/proofs/Iden3SparseMerkleTreeProof-v2.md#issuerData"},
		q.Predicate)

	idx, err = findParent(ds, q)
	require.NoError(t, err)
	q = findQuadByIdx(t, ds, idx)
	assert.Equal(t,
		&ld.IRI{Value: "https://www.w3.org/2018/credentials#verifiableCredential"},
		q.Predicate)

	_, err = findParent(ds, q)
	require.ErrorIs(t, err, errParentNotFound)
}

func TestEmbeddedSchemas(t *testing.T) {
	defer tst.MockHTTPClient(t,
		map[string]string{
			"https://www.w3.org/2018/credentials/v1": "testdata/httpresp/credentials-v1.jsonld",
			// These docs should be gotten from the cache
			// "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":             "testdata/httpresp/kyc-v3.json-ld",
			// "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld": "testdata/httpresp/iden3credential-v2.json-ld",
		},
		tst.IgnoreUntouchedURLs())()

	kycBytes, err := os.ReadFile("testdata/httpresp/kyc-v3.json-ld")
	require.NoError(t, err)

	iden3CredentialBytes, err := os.ReadFile("testdata/httpresp/iden3credential-v2.json-ld")
	require.NoError(t, err)

	ctx := context.Background()
	cacheEng, err := loaders.NewMemoryCacheEngine(
		loaders.WithEmbeddedDocumentBytes(
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
			kycBytes),
		loaders.WithEmbeddedDocumentBytes(
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld",
			iden3CredentialBytes))
	require.NoError(t, err)

	docLoader := loaders.NewDocumentLoader(nil, "",
		loaders.WithCacheEngine(cacheEng))

	mz, err := MerklizeJSONLD(ctx, strings.NewReader(multigraphDoc2),
		WithDocumentLoader(docLoader))
	require.NoError(t, err)
	require.Equal(t,
		"11252837464697009054213269776498742372491493851016505396927630745348533726396",
		mz.Root().BigInt().String())
}

var multigraphDocURLMaps = map[string]string{
	"https://www.w3.org/2018/credentials/v1":                                                         "testdata/httpresp/credentials-v1.jsonld",
	"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld": "testdata/httpresp/kyc-v3.json-ld",
}

const multigraphDoc = `{
  "@context":[
    "https://www.w3.org/2018/credentials/v1",
    "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld"
  ],
  "@type":"VerifiablePresentation",
  "holder": ["http://example.com/holder1", "http://example.com/holder2"],
  "verifiableCredential": {
    "@id": "http://example.com/vc2",
    "@type":"KYCAgeCredential",
    "birthday":19960425
  }
}`

func TestMerklizer_RawValue(t *testing.T) {
	defer tst.MockHTTPClient(t, multigraphDocURLMaps,
		tst.IgnoreUntouchedURLs())()
	ctx := context.Background()
	mz, err := MerklizeJSONLD(ctx, strings.NewReader(multigraphDoc))
	require.NoError(t, err)

	path, err := NewPathFromDocument([]byte(multigraphDoc),
		"verifiableCredential.birthday")
	require.NoError(t, err)

	val, err := mz.RawValue(path)
	require.NoError(t, err)
	require.Equal(t, float64(19960425), val)
}

var vcURLMaps = map[string]string{
	"https://www.w3.org/2018/credentials/v1":                                                           "testdata/httpresp/credentials-v1.jsonld",
	"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld": "testdata/httpresp/kyc-v101.json-ld",
}

var vc = `
{
  "verifiableCredential": {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld"
    ],
    "@type": [
      "VerifiableCredential",
      "KYCEmployee"
    ],
    "credentialSubject": {
      "@type": "KYCEmployee",
      "salary": 170000
    }
  },
  "@type": "VerifiablePresentation",
  "@context": [
    "https://www.w3.org/2018/credentials/v1"
  ]
}`

func TestFloatNormalization(t *testing.T) {
	defer tst.MockHTTPClient(t, vcURLMaps, tst.IgnoreUntouchedURLs())()
	ctx := context.Background()
	mz, err := MerklizeJSONLD(ctx, strings.NewReader(vc))
	require.NoError(t, err)

	path, err := mz.ResolveDocPath("verifiableCredential.credentialSubject.salary")
	require.NoError(t, err)

	_, v, err := mz.Proof(context.Background(), path)
	require.NoError(t, err)

	i, err := v.MtEntry()
	require.NoError(t, err)

	// Test that float value is normalized to 1.7E5
	i2, err := poseidon.HashBytes([]byte("1.7E5"))
	require.NoError(t, err)
	require.Equal(t, i.String(), i2.String())

	datatype, err := mz.JSONLDType(path)
	require.NoError(t, err)
	require.Equal(t, "http://www.w3.org/2001/XMLSchema#double", datatype)
	// Test we generated correct hash for float64(170000) converted it to 1.7E5
	i3, err := HashValue(datatype, float64(170000))
	require.NoError(t, err)
	require.Equal(t, i.String(), i3.String())
}

func TestIncorrectDocument_UnsafeMode(t *testing.T) {
	const docUnknownFields = `{
    "id": "http://127.0.0.1/id",
    "expirationDate": "2030-01-01T00:00:00Z"
}`

	ctx := context.Background()

	t.Run("default safe mode", func(t *testing.T) {
		_, err := MerklizeJSONLD(ctx, strings.NewReader(docUnknownFields))
		require.EqualError(t, err,
			"invalid property: Dropping property that did not expand into an absolute IRI or keyword.")

	})

	t.Run("explicitly set safe mode", func(t *testing.T) {
		_, err := MerklizeJSONLD(ctx, strings.NewReader(docUnknownFields),
			WithSafeMode(true))
		require.EqualError(t, err,
			"invalid property: Dropping property that did not expand into an absolute IRI or keyword.")
	})

	t.Run("explicitly set unsafe mode", func(t *testing.T) {
		_, err := MerklizeJSONLD(ctx, strings.NewReader(docUnknownFields),
			WithSafeMode(false))
		require.NoError(t, err)
	})
}

func TestTypeFromContext(t *testing.T) {
	ctxBytes, err := os.ReadFile("testdata/kyc_schema.json-ld")
	require.NoError(t, err)

	pathToField := "KYCAgeCredential.birthday"
	typ, err := TypeFromContext(ctxBytes, pathToField)
	require.NoError(t, err)
	require.Equal(t, "http://www.w3.org/2001/XMLSchema#integer", typ)
}

func TestTypeIDFromContext(t *testing.T) {
	t.Run("url-like id", func(t *testing.T) {
		ctxBytes, err := os.ReadFile("testdata/kyc_schema.json-ld")
		require.NoError(t, err)

		typeName := "KYCCountryOfResidenceCredential"
		typeID, err := TypeIDFromContext(ctxBytes, typeName)
		require.NoError(t, err)
		require.Equal(t,
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v4.json-ld#KYCCountryOfResidenceCredential",
			typeID)
	})

	t.Run("urn-like id", func(t *testing.T) {
		ctxBytes, err := os.ReadFile("testdata/kyc-v102.jsonld")
		require.NoError(t, err)

		typeName := "KYCCountryOfResidenceCredential"
		typeID, err := TypeIDFromContext(ctxBytes, typeName)
		require.NoError(t, err)
		require.Equal(t, "urn:uuid:a81d4fae-7dec-11d0-a765-00a0c91e6bf0",
			typeID)
	})
}

func TestHashValues_FromDocument(t *testing.T) {
	ctxBytes, err := os.ReadFile("testdata/kyc_schema.json-ld")
	require.NoError(t, err)

	ctxBytes2, err := os.ReadFile("testdata/custom_schema.json")
	require.NoError(t, err)

	tests := []struct {
		name        string
		ctxBytes    []byte
		pathToField string
		datatype    string
		value       interface{}
		wantHash    string
		wantHashErr string
	}{
		{
			name:        "xsd:integer",
			pathToField: "KYCEmployee.documentType",
			datatype:    "http://www.w3.org/2001/XMLSchema#integer",
			value:       1,
			wantHash:    "1",
		},
		{
			name:        "xsd:boolean true",
			pathToField: "KYCEmployee.ZKPexperiance",
			datatype:    "http://www.w3.org/2001/XMLSchema#boolean",
			value:       true,
			wantHash:    "18586133768512220936620570745912940619677854269274689475585506675881198879027",
		},
		{
			name:        "xsd:boolean false",
			pathToField: "KYCEmployee.ZKPexperiance",
			datatype:    "http://www.w3.org/2001/XMLSchema#boolean",
			value:       false,
			wantHash:    "19014214495641488759237505126948346942972912379615652741039992445865937985820",
		},
		{
			name:        "xsd:boolean 1",
			pathToField: "KYCEmployee.ZKPexperiance",
			datatype:    "http://www.w3.org/2001/XMLSchema#boolean",
			value:       "1",
			wantHash:    "18586133768512220936620570745912940619677854269274689475585506675881198879027",
		},
		{
			name:        "xsd:boolean 0",
			pathToField: "KYCEmployee.ZKPexperiance",
			datatype:    "http://www.w3.org/2001/XMLSchema#boolean",
			value:       "0",
			wantHash:    "19014214495641488759237505126948346942972912379615652741039992445865937985820",
		},
		{
			name:        "xsd:dateTime > January 1st, 1970 RFC3339Nano",
			pathToField: "KYCEmployee.hireDate",
			datatype:    "http://www.w3.org/2001/XMLSchema#dateTime",
			value:       "2019-01-01T00:00:00Z",
			wantHash:    "1546300800000000000",
		},
		{
			name:        "xsd:dateTime < January 1st, 1970 RFC3339Nano",
			pathToField: "KYCEmployee.hireDate",
			datatype:    "http://www.w3.org/2001/XMLSchema#dateTime",
			value:       "1960-02-20T11:20:33Z",
			wantHash:    "21888242871839275222246405745257275088548364400416034343697892928208808495617",
		},
		{
			name:        "xsd:dateTime YYYY-MM-DD go format (2006-01-02)",
			pathToField: "KYCEmployee.hireDate",
			datatype:    "http://www.w3.org/2001/XMLSchema#dateTime",
			value:       "1997-04-16",
			wantHash:    "861148800000000000",
		},
		{
			name:        "xsd:string",
			pathToField: "KYCEmployee.position",
			datatype:    "http://www.w3.org/2001/XMLSchema#string",
			value:       "SSI Consultant",
			wantHash:    "957410455271905675920624030785024750144198809104092676617070098470852489834",
		},
		{
			name:        "xsd:double should be processed as string",
			pathToField: "KYCEmployee.salary",
			datatype:    "http://www.w3.org/2001/XMLSchema#double",
			value:       100000.01,
			wantHash:    "7858939477831965477428998013961435925262790627337131132863073454519451718017",
		},
		{
			name:        "xsd:double in our case will be processed as string, since rules are not defined",
			pathToField: "KYCEmployee.salary",
			datatype:    "http://www.w3.org/2001/XMLSchema#double",
			value:       "100000.01",
			wantHash:    "7858939477831965477428998013961435925262790627337131132863073454519451718017",
		},
		{
			name:        "big float64 should be correctly parsed as integer",
			pathToField: "KYCCountryOfResidenceCredential.countryCode",
			datatype:    "http://www.w3.org/2001/XMLSchema#integer",
			value:       float64(19960424),
			wantHash:    "19960424",
		},
		{
			name:        "max value for positive integer",
			ctxBytes:    ctxBytes2,
			pathToField: "TestType1.positiveNumber",
			datatype:    "http://www.w3.org/2001/XMLSchema#positiveInteger",
			value:       "21888242871839275222246405745257275088548364400416034343698204186575808495616",
			wantHash:    "21888242871839275222246405745257275088548364400416034343698204186575808495616",
		},
		{
			name:        "max value for positive integer - too large error",
			ctxBytes:    ctxBytes2,
			pathToField: "TestType1.positiveNumber",
			datatype:    "http://www.w3.org/2001/XMLSchema#positiveInteger",
			value:       "21888242871839275222246405745257275088548364400416034343698204186575808495617",
			wantHashErr: "integer exceeds maximum value: 21888242871839275222246405745257275088548364400416034343698204186575808495617",
		},
		{
			name:        "max value for positive integer - negative error",
			ctxBytes:    ctxBytes2,
			pathToField: "TestType1.positiveNumber",
			datatype:    "http://www.w3.org/2001/XMLSchema#positiveInteger",
			value:       "-100500",
			wantHashErr: "integer is below minimum value: -100500",
		},
		{
			name:        "max value for integer",
			pathToField: "KYCCountryOfResidenceCredential.countryCode",
			datatype:    "http://www.w3.org/2001/XMLSchema#integer",
			value:       "10944121435919637611123202872628637544274182200208017171849102093287904247808",
			wantHash:    "10944121435919637611123202872628637544274182200208017171849102093287904247808",
		},
		{
			name:        "max value for integer - too large error",
			pathToField: "KYCCountryOfResidenceCredential.countryCode",
			datatype:    "http://www.w3.org/2001/XMLSchema#integer",
			value:       "10944121435919637611123202872628637544274182200208017171849102093287904247809",
			wantHashErr: "integer exceeds maximum value: 10944121435919637611123202872628637544274182200208017171849102093287904247809",
		},
		{
			name:        "max value for integer - -1",
			pathToField: "KYCCountryOfResidenceCredential.countryCode",
			datatype:    "http://www.w3.org/2001/XMLSchema#integer",
			value:       "-1",
			wantHash:    "21888242871839275222246405745257275088548364400416034343698204186575808495616",
		},
		{
			name:        "max value for integer - minimum value",
			pathToField: "KYCCountryOfResidenceCredential.countryCode",
			datatype:    "http://www.w3.org/2001/XMLSchema#integer",
			value:       "-10944121435919637611123202872628637544274182200208017171849102093287904247808",
			wantHash:    "10944121435919637611123202872628637544274182200208017171849102093287904247809",
		},
		{
			name:        "max value for integer - too small error",
			pathToField: "KYCCountryOfResidenceCredential.countryCode",
			datatype:    "http://www.w3.org/2001/XMLSchema#integer",
			value:       "-10944121435919637611123202872628637544274182200208017171849102093287904247809",
			wantHashErr: "integer is below minimum value: -10944121435919637611123202872628637544274182200208017171849102093287904247809",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ldContext := ctxBytes
			if tt.ctxBytes != nil {
				ldContext = tt.ctxBytes
			}
			actualType, err := TypeFromContext(ldContext, tt.pathToField)
			require.NoError(t, err)
			require.Equal(t, tt.datatype, actualType)

			actualHash, err := HashValue(tt.datatype, tt.value)
			if tt.wantHashErr == "" {
				require.NoError(t, err)
				require.Equal(t, tt.wantHash, actualHash.String())
			} else {
				require.EqualError(t, err, tt.wantHashErr)
			}
		})
	}
}

func TestHashValue(t *testing.T) {
	tests := []struct {
		name     string
		datatype string
		value    interface{}
		wantHash string
		wantErr  string
	}{
		{
			name:     "xsd:integer",
			datatype: "http://www.w3.org/2001/XMLSchema#integer",
			value:    1,
			wantHash: "1",
		},
		{
			name:     "xsd:boolean true",
			datatype: "http://www.w3.org/2001/XMLSchema#boolean",
			value:    true,
			wantHash: "18586133768512220936620570745912940619677854269274689475585506675881198879027",
		},
		{
			name:     "xsd:boolean false",
			datatype: "http://www.w3.org/2001/XMLSchema#boolean",
			value:    false,
			wantHash: "19014214495641488759237505126948346942972912379615652741039992445865937985820",
		},
		{
			name:     "xsd:boolean 1",
			datatype: "http://www.w3.org/2001/XMLSchema#boolean",
			value:    "1",
			wantHash: "18586133768512220936620570745912940619677854269274689475585506675881198879027",
		},
		{
			name:     "xsd:boolean 0",
			datatype: "http://www.w3.org/2001/XMLSchema#boolean",
			value:    "0",
			wantHash: "19014214495641488759237505126948346942972912379615652741039992445865937985820",
		},
		{
			name:     "xsd:dateTime > January 1st, 1970 RFC3339Nano",
			datatype: "http://www.w3.org/2001/XMLSchema#dateTime",
			value:    "2019-01-01T00:00:00Z",
			wantHash: "1546300800000000000",
		},
		{
			name:     "xsd:dateTime in the distant future",
			datatype: "http://www.w3.org/2001/XMLSchema#dateTime",
			value:    "4000-01-01T00:00:00Z",
			wantHash: "64060588800000000000",
		},
		{
			name:     "xsd:dateTime < January 1st, 1970 RFC3339Nano",
			datatype: "http://www.w3.org/2001/XMLSchema#dateTime",
			value:    "1960-02-20T11:20:33Z",
			wantHash: "21888242871839275222246405745257275088548364400416034343697892928208808495617",
		},
		{
			name:     "xsd:dateTime YYYY-MM-DD go format (2006-01-02)",
			datatype: "http://www.w3.org/2001/XMLSchema#dateTime",
			value:    "1997-04-16",
			wantHash: "861148800000000000",
		},
		{
			name:     "xsd:string",
			datatype: "http://www.w3.org/2001/XMLSchema#string",
			value:    "SSI Consultant",
			wantHash: "957410455271905675920624030785024750144198809104092676617070098470852489834",
		},
		{
			name:     "xsd:double should be processed as string",
			datatype: "http://www.w3.org/2001/XMLSchema#double",
			value:    100000.01,
			wantHash: "7858939477831965477428998013961435925262790627337131132863073454519451718017",
		},
		{
			name:     "xsd:double in our case will be processed as string, since rules are not defined",
			datatype: "http://www.w3.org/2001/XMLSchema#double",
			value:    "100000.01",
			wantHash: "7858939477831965477428998013961435925262790627337131132863073454519451718017",
		},
		{
			name:     "big float64 should be correctly parsed as integer",
			datatype: "http://www.w3.org/2001/XMLSchema#integer",
			value:    float64(19960424),
			wantHash: "19960424",
		},
		{
			name:     "int32 with double xsd type should be correctly parsed as string",
			datatype: "http://www.w3.org/2001/XMLSchema#double",
			value:    int32(19960424),
			// hash of "1.9960424E7"
			wantHash: "14659279547748882579324236944917252187779632081828519649786308744097131655268",
		},
		{
			name:     "uint32 with double xsd type should be correctly parsed as string",
			datatype: "http://www.w3.org/2001/XMLSchema#double",
			value:    uint32(19960424),
			wantHash: strHash("1.9960424E7"),
		},
		{
			name:     "uint64 is too big for float64",
			datatype: "http://www.w3.org/2001/XMLSchema#double",
			value:    uint64(math.MaxUint64) - 1,
			wantErr:  "value is too big to be converted to float64",
		},
		{
			name:     "uint64 is too big for float64 (special case with max uint64)",
			datatype: "http://www.w3.org/2001/XMLSchema#double",
			value:    uint64(math.MaxUint64),
			wantErr:  "value is too big to be converted to float64",
		},
		{
			name:     "int64 is too big for float64",
			datatype: "http://www.w3.org/2001/XMLSchema#double",
			value:    int64(math.MaxInt64),
			wantErr:  "value is too big to be converted to float64",
		},
		{
			name:     "near to max int64 that may be hashed",
			datatype: "http://www.w3.org/2001/XMLSchema#double",
			value:    int64(1234567890123456),
			wantHash: strHash("1.234567890123456E15"),
		},
		{
			name:     "false boolean xsd type with float64(0) value",
			datatype: "http://www.w3.org/2001/XMLSchema#boolean",
			value:    float64(0),
			wantHash: "19014214495641488759237505126948346942972912379615652741039992445865937985820",
		},
		{
			name:     "boolean xsd type with float64(1) value",
			datatype: "http://www.w3.org/2001/XMLSchema#boolean",
			value:    float64(1),
			wantHash: "18586133768512220936620570745912940619677854269274689475585506675881198879027",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualHash, err := HashValue(tt.datatype, tt.value)
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.wantHash, actualHash.String())
			}
		})
	}
}

func strHash(str string) string {
	i, err := poseidon.HashBytes([]byte(str))
	if err != nil {
		panic(err)
	}
	return i.String()
}

func TestHashValue_Errors(t *testing.T) {
	ctxBytes, err := os.ReadFile("testdata/kyc_schema.json-ld")
	require.NoError(t, err)

	tests := []struct {
		name        string
		pathToField string
		datatype    string
		value       interface{}
		wantErr     string
	}{
		{
			name:        "xsd:boolean invalid value",
			pathToField: "KYCEmployee.ZKPexperiance",
			datatype:    "http://www.w3.org/2001/XMLSchema#boolean",
			value:       "True",
			wantErr:     "incorrect boolean value",
		},
		{
			name:        "xsd:integer invalid value",
			pathToField: "KYCEmployee.documentType",
			datatype:    "http://www.w3.org/2001/XMLSchema#integer",
			value:       "one",
			wantErr:     "can't parse number: one",
		},
		{
			name:        "xsd:dateTime invalid format MM-DD-YYYY go format (01-02-2006)",
			pathToField: "KYCEmployee.hireDate",
			datatype:    "http://www.w3.org/2001/XMLSchema#dateTime",
			value:       "01-01-2019",
			wantErr:     "parsing time \"01-01-2019\"",
		},
		{
			name:        "unknown datatype",
			pathToField: "KYCEmployee.documentType",
			datatype:    "http://www.w3.org/2001/XMLSchema#integer",
			value:       []byte{1},
			wantErr:     ErrorUnsupportedType.Error(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualType, err := TypeFromContext(ctxBytes, tt.pathToField)
			require.NoError(t, err)
			require.Equal(t, tt.datatype, actualType)

			_, actualErr := HashValue(tt.datatype, tt.value)
			require.Error(t, actualErr)
			require.Contains(t, actualErr.Error(), tt.wantErr)
		})
	}
}

type testHasher struct{}

func (h testHasher) Hash(inpBI []*big.Int) (*big.Int, error) {
	return poseidon.Hash(inpBI)
}

func (h testHasher) HashBytes(msg []byte) (*big.Int, error) {
	return poseidon.HashBytesX(msg, 6)
}

func (h testHasher) Prime() *big.Int {
	return new(big.Int).Set(constants.Q)
}

// Test consistency of WithHasher usage. Proof should be generated with path
// created with ResolveDocPath method of Merklizer.
func TestWithHasherWorkflow(t *testing.T) {
	const testPresentationDoc = `
{
  "id": "uuid:presentation:12312",
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://raw.githubusercontent.com/demonsh/schema/main/jsonld/presentation.json-ld#Presentation"
  ],
  "type": [
    "VerifiableCredential"
  ],
  "expirationDate": "2024-03-08T22:02:16Z",
  "issuanceDate": "2023-03-08T22:02:16Z",
  "issuer": "did:pkh:eip155:1:0x1e903ddDFf29f13fC62F3c78c5b5622a3b14752c",
  "credentialSubject": {
    "id": "did:pkh:eip155:1:0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
    "score": 64,
    "type": "Presentation"
  }
}`

	mz, _ := MerklizeJSONLD(context.Background(),
		strings.NewReader(testPresentationDoc),
		WithHasher(testHasher{}))

	p, err := mz.ResolveDocPath("credentialSubject")
	require.NoError(t, err)

	fieldProof, fieldValue, err := mz.Proof(context.Background(), p)
	require.NoError(t, err)

	require.True(t, fieldProof.Existence)

	value1, err := fieldValue.MtEntry()
	require.NoError(t, err)
	require.NotNil(t, value1)
}

func TestMerklizer_JSONLDType(t *testing.T) {
	defer tst.MockHTTPClient(t, testDocumentURLMaps,
		tst.IgnoreUntouchedURLs())()

	ctx := context.Background()
	mz, err := MerklizeJSONLD(ctx, strings.NewReader(testDocument))
	require.NoError(t, err)

	t.Run("xsd:dateTime", func(t *testing.T) {
		path, err := NewPath(
			"https://www.w3.org/2018/credentials#credentialSubject", 1,
			"http://schema.org/birthDate")
		require.NoError(t, err)

		datatype, err := mz.JSONLDType(path)
		require.NoError(t, err)
		require.Equal(t, "http://www.w3.org/2001/XMLSchema#dateTime", datatype)
	})

	t.Run("empty datatype", func(t *testing.T) {
		path, err := NewPath(
			"https://www.w3.org/2018/credentials#credentialSubject", 0,
			"http://www.w3.org/1999/02/22-rdf-syntax-ns#type", 0)
		require.NoError(t, err)

		datatype, err := mz.JSONLDType(path)
		require.NoError(t, err)
		require.Equal(t, "", datatype)
	})
}

var docWithFloat = `{
  "http://example.com/field1": {
    "@type": "http://www.w3.org/2001/XMLSchema#double",
    "@value": 123
  },
  "http://example.com/field2": {
    "@type": "http://www.w3.org/2001/XMLSchema#double",
    "@value": "123"
  }
}`

func TestRoots(t *testing.T) {
	defer tst.MockHTTPClient(t,
		mergeMaps(multigraphDoc2URLMaps, testDocumentURLMaps, doc1URLMaps,
			vcURLMaps),
		tst.IgnoreUntouchedURLs())()

	testcases := []struct {
		name     string
		doc      string
		wantRoot string
	}{
		{
			name:     "testDocument",
			doc:      testDocument,
			wantRoot: "19309047812100087948241250053335720576191969395309912987389452441269932261840",
		},
		{
			name:     "doc1",
			doc:      doc1,
			wantRoot: "14254126130605812747518773069191924472136034086074656038330159471066163388520",
		},
		{
			name:     "multigraphDoc2",
			doc:      multigraphDoc2,
			wantRoot: "11252837464697009054213269776498742372491493851016505396927630745348533726396",
		},
		{
			name:     "vc",
			doc:      vc,
			wantRoot: "438107724194342316220762948074408676879297288866380839121721382436955105096",
		},
		{
			name:     "docWithFloat",
			doc:      docWithFloat,
			wantRoot: "16807151140873243281836480228059250043791482248223749610516824774207131149216",
		},
	}
	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			mz, err := MerklizeJSONLD(context.Background(),
				strings.NewReader(tt.doc))
			require.NoError(t, err)

			root := mz.Root()
			require.Equal(t, tt.wantRoot, root.BigInt().String())
		})
	}
}

const ipfsDocument = `{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "{{ .CitizenshipContext }}",
	"{{ .BBSContext }}"
  ],
  "id": "https://issuer.oidp.uscis.gov/credentials/83627465",
  "type": ["VerifiableCredential", "PermanentResidentCard"],
  "issuer": "did:example:489398593",
  "identifier": 83627465,
  "name": "Permanent Resident Card",
  "description": "Government of Example Permanent Resident Card.",
  "issuanceDate": "2019-12-03T12:19:52Z",
  "expirationDate": "2029-12-03T12:19:52Z",
  "credentialSubject": [
    {
      "id": "did:example:b34ca6cd37bbf23",
      "type": ["PermanentResident", "Person"],
      "givenName": "JOHN",
      "familyName": "SMITH",
      "gender": "Male",
      "image": "data:image/png;base64,iVBORw0KGgokJggg==",
      "residentSince": "2015-01-01",
      "lprCategory": "C09",
      "lprNumber": "999-999-999",
      "commuterClassification": "C1",
      "birthCountry": "Bahamas",
      "birthDate": "1958-07-17"
    },
    {
      "id": "did:example:b34ca6cd37bbf24",
      "type": ["PermanentResident", "Person"],
      "givenName": "JOHN",
      "familyName": "SMITH",
      "gender": "Male",
      "image": "data:image/png;base64,iVBORw0KGgokJggg==",
      "residentSince": "2015-01-01",
      "lprCategory": "C09",
      "lprNumber": "999-999-999",
      "commuterClassification": "C1",
      "birthCountry": "Bahamas",
      "birthDate": "1958-07-18"
    }
  ]
}`

type mockIPFSLoader map[string]string

func (m mockIPFSLoader) Cat(url string) (io.ReadCloser, error) {
	fName, ok := m[url]
	if !ok {
		return nil, errors.New("not found")
	}
	return os.Open(fName)
}

func TestIPFSContext(t *testing.T) {

	citizenshipCtx := "Qmbp4kwoHULnmK71abrxdksjPH5sAjxSAXU5PEp2XRMFNw/dir2/bbs-v2.jsonld"
	bbsCtx := "QmdP4MZkESEabRVB322r2xWm7TCi7LueMNWMJawYmSy7hp"

	defer tst.MockHTTPClient(t, testDocumentIPFSURLMaps,
		tst.IgnoreUntouchedURLs())()

	ipfsCli := mockIPFSLoader{
		citizenshipCtx: "testdata/ipfs/dir1/dir2/bbs-v2.jsonld",
		bbsCtx:         "testdata/ipfs/citizenship-v1.jsonld",
		"QmeMevwUeD7o6hjfmdaeFD1q4L84hSDiRjeXZLi1bZK1My": "testdata/ipfs/testNewType.jsonld",
	}

	tmpl := template.Must(template.New("").Parse(ipfsDocument))
	b := bytes.NewBuffer(nil)
	err := tmpl.Execute(b, map[string]interface{}{
		"CitizenshipContext": "ipfs://" + citizenshipCtx,
		"BBSContext":         "ipfs://" + bbsCtx,
	})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	t.Run("no ipfs client", func(t *testing.T) {
		_, err = MerklizeJSONLD(ctx, bytes.NewReader(b.Bytes()))
		require.ErrorContains(t, err,
			"loading document failed: ipfs is not configured")
	})

	t.Run("with ipfs client", func(t *testing.T) {
		mz, err2 := MerklizeJSONLD(ctx, bytes.NewReader(b.Bytes()),
			WithIPFSClient(ipfsCli))
		require.NoError(t, err2)
		require.Equal(t,
			"19309047812100087948241250053335720576191969395309912987389452441269932261840",
			mz.Root().BigInt().String())
	})

	t.Run("with default ipfs client", func(t *testing.T) {
		oldDocLoader := defaultDocumentLoader
		t.Cleanup(func() { SetDocumentLoader(oldDocLoader) })

		docLoader := loaders.NewDocumentLoader(ipfsCli, "")
		SetDocumentLoader(docLoader)

		mz, err2 := MerklizeJSONLD(ctx, bytes.NewReader(b.Bytes()))
		require.NoError(t, err2)
		require.Equal(t,
			"19309047812100087948241250053335720576191969395309912987389452441269932261840",
			mz.Root().BigInt().String())
	})

	// If both IPFS client and gateway URL are provided, the client is used.
	t.Run("with ipfs client and gateway URL", func(t *testing.T) {
		mz, err2 := MerklizeJSONLD(ctx, bytes.NewReader(b.Bytes()),
			WithIPFSClient(ipfsCli),
			WithIPFSGateway("http://ipfs.io"))
		require.NoError(t, err2)
		require.Equal(t,
			"19309047812100087948241250053335720576191969395309912987389452441269932261840",
			mz.Root().BigInt().String())
	})

	t.Run("with ipfs gateway", func(t *testing.T) {
		ipfsGW := "http://ipfs.io"
		defer tst.MockHTTPClient(t, map[string]string{
			"https://www.w3.org/2018/credentials/v1":                                           "testdata/httpresp/credentials-v1.jsonld",
			ipfsGW + "/ipfs/QmdP4MZkESEabRVB322r2xWm7TCi7LueMNWMJawYmSy7hp":                    "testdata/ipfs/citizenship-v1.jsonld",
			ipfsGW + "/ipfs/Qmbp4kwoHULnmK71abrxdksjPH5sAjxSAXU5PEp2XRMFNw/dir2/bbs-v2.jsonld": "testdata/ipfs/dir1/dir2/bbs-v2.jsonld",
		})()

		mz, err2 := MerklizeJSONLD(ctx, bytes.NewReader(b.Bytes()),
			WithIPFSGateway(ipfsGW))
		require.NoError(t, err2)
		require.Equal(t,
			"19309047812100087948241250053335720576191969395309912987389452441269932261840",
			mz.Root().BigInt().String())
	})

	t.Run("with document loader", func(t *testing.T) {
		docLoader := loaders.NewDocumentLoader(ipfsCli, "")
		mz, err2 := MerklizeJSONLD(ctx, bytes.NewReader(b.Bytes()),
			WithDocumentLoader(docLoader))
		require.NoError(t, err2)
		require.Equal(t,
			"19309047812100087948241250053335720576191969395309912987389452441269932261840",
			mz.Root().BigInt().String())
	})

	t.Run("NewPathFromDocument with default document loader", func(t *testing.T) {
		oldDefaultDocumentLoader := defaultDocumentLoader
		t.Cleanup(func() {
			SetDocumentLoader(oldDefaultDocumentLoader)
		})

		docLoader := loaders.NewDocumentLoader(ipfsCli, "")
		SetDocumentLoader(docLoader)

		in := "credentialSubject.1.testNewTypeInt"
		result, err := NewPathFromDocument([]byte(testDocumentIPFS), in)
		require.NoError(t, err)

		want, err := NewPath(
			"https://www.w3.org/2018/credentials#credentialSubject",
			1,
			"urn:uuid:0a8092e3-7100-4068-ba67-fae502cc6e7b#testNewTypeInt")
		require.NoError(t, err)

		require.Equal(t, want, result)
	})

	t.Run("NewPathFromDocument with document loader option", func(t *testing.T) {
		docLoader := loaders.NewDocumentLoader(ipfsCli, "")
		opts := Options{DocumentLoader: docLoader}

		in := "credentialSubject.1.testNewTypeInt"
		result, err := opts.NewPathFromDocument([]byte(testDocumentIPFS), in)
		require.NoError(t, err)

		want, err := NewPath(
			"https://www.w3.org/2018/credentials#credentialSubject",
			1,
			"urn:uuid:0a8092e3-7100-4068-ba67-fae502cc6e7b#testNewTypeInt")
		require.NoError(t, err)

		require.Equal(t, want, result)
	})

}

func mergeMaps(ms ...map[string]string) map[string]string {
	res := make(map[string]string)
	for _, m := range ms {
		for k, v := range m {
			res[k] = v
		}
	}

	return res
}
