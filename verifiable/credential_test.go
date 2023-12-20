package verifiable

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	mt "github.com/iden3/go-merkletree-sql/v2"
	tst "github.com/iden3/go-schema-processor/v2/testing"
	"github.com/stretchr/testify/require"
)

func TestW3CCredential_ValidateBJJSignatureProof(t *testing.T) {
	in := `{
    "id": "urn:uuid:a53e3cd8-9f4f-11ee-bf48-a27b3ddbdc29",
    "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://schema.iden3.io/core/jsonld/iden3proofs.jsonld",
        "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-nonmerklized.jsonld"
    ],
    "type": [
        "VerifiableCredential",
        "KYCAgeCredential"
    ],
    "expirationDate": "2361-03-21T21:14:48+02:00",
    "issuanceDate": "2023-12-20T17:51:31.86152+02:00",
    "credentialSubject": {
        "birthday": 19960424,
        "documentType": 99,
        "id": "did:polygonid:polygon:mumbai:2qGvDQksBFJUkzcmBjxkLkuZmjyyzhvAqXe4i3Vsak",
        "type": "KYCAgeCredential"
    },
    "credentialStatus": {
        "id": "https://ad40-91-210-251-7.ngrok-free.app/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qFdiASbojMMsUzEo3Qg7pbhoD52hfm2qDJmtbRgQU/claims/revocation/status/1401486356",
        "revocationNonce": 1401486356,
        "type": "SparseMerkleTreeProof"
    },
    "issuer": "did:polygonid:polygon:mumbai:2qFdiASbojMMsUzEo3Qg7pbhoD52hfm2qDJmtbRgQU",
    "credentialSchema": {
        "id": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/kyc-nonmerklized.json",
        "type": "JsonSchema2023"
    },
    "proof": [
        {
            "type": "BJJSignature2021",
            "issuerData": {
                "id": "did:polygonid:polygon:mumbai:2qFdiASbojMMsUzEo3Qg7pbhoD52hfm2qDJmtbRgQU",
                "state": {
                    "claimsTreeRoot": "2409619cd18e0b1a10fc897d9827c5723d80ba58963a3c187acedacb799bf913",
                    "value": "97cc72ecbc45be89f373597dd4eb00a7d8ed3bbc29583fc333cb2b388359dc00"
                },
                "authCoreClaim": "cca3371a6cb1b715004407e325bd993c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001375c486e37e4309dc1e6d81f7c5a648e1a0b1d86a3634b34b5fe8222c1442290f9ba55931a9a891f45790b01b6eaae4131ccf22ba81eecc0053dc059de8fb020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "mtp": {
                    "existence": true,
                    "siblings": []
                },
                "credentialStatus": {
                    "id": "https://ad40-91-210-251-7.ngrok-free.app/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qFdiASbojMMsUzEo3Qg7pbhoD52hfm2qDJmtbRgQU/claims/revocation/status/0",
                    "revocationNonce": 0,
                    "type": "SparseMerkleTreeProof"
                }
            },
            "coreClaim": "cb373906ed88fff9332f71521b712c950a0000000000000000000000000000000212620a53d8184c2ae591951aa8e3f3e1fcd48ea329b858cf5c762d22e70d006892300100000000000000000000000000000000000000000000000000000000630000000000000000000000000000000000000000000000000000000000000014fc885300000000281cdcdf0200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "signature": "1dd9f4da6b5595e6440b986f726644e5cf0148d8b62416e46001d55edd56d88bde86e8f5232a0171076f3d1e570ea6210b26b60ed3087a6b778735ee03946205"
        }
    ]
}`
	var vc W3CCredential
	err := json.Unmarshal([]byte(in), &vc)

	isValid, err := vc.ValidateProof(context.Background(), BJJSignatureProofType)
	require.NoError(t, err)
	require.True(t, isValid)
}

func TestW3CCredential_ValidateIden3SparseMerkleTreeProof(t *testing.T) {
	in := `{
    "id": "urn:uuid:a53e3cd8-9f4f-11ee-bf48-a27b3ddbdc29",
    "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://schema.iden3.io/core/jsonld/iden3proofs.jsonld",
        "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-nonmerklized.jsonld"
    ],
    "type": [
        "VerifiableCredential",
        "KYCAgeCredential"
    ],
    "expirationDate": "2361-03-21T21:14:48+02:00",
    "issuanceDate": "2023-12-20T17:51:31.86152+02:00",
    "credentialSubject": {
        "birthday": 19960424,
        "documentType": 99,
        "id": "did:polygonid:polygon:mumbai:2qGvDQksBFJUkzcmBjxkLkuZmjyyzhvAqXe4i3Vsak",
        "type": "KYCAgeCredential"
    },
    "credentialStatus": {
        "id": "https://ad40-91-210-251-7.ngrok-free.app/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qFdiASbojMMsUzEo3Qg7pbhoD52hfm2qDJmtbRgQU/claims/revocation/status/1401486356",
        "revocationNonce": 1401486356,
        "type": "SparseMerkleTreeProof"
    },
    "issuer": "did:polygonid:polygon:mumbai:2qFdiASbojMMsUzEo3Qg7pbhoD52hfm2qDJmtbRgQU",
    "credentialSchema": {
        "id": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/kyc-nonmerklized.json",
        "type": "JsonSchema2023"
    },
    "proof": [
        {
            "type": "BJJSignature2021",
            "issuerData": {
                "id": "did:polygonid:polygon:mumbai:2qFdiASbojMMsUzEo3Qg7pbhoD52hfm2qDJmtbRgQU",
                "state": {
                    "claimsTreeRoot": "2409619cd18e0b1a10fc897d9827c5723d80ba58963a3c187acedacb799bf913",
                    "value": "97cc72ecbc45be89f373597dd4eb00a7d8ed3bbc29583fc333cb2b388359dc00"
                },
                "authCoreClaim": "cca3371a6cb1b715004407e325bd993c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001375c486e37e4309dc1e6d81f7c5a648e1a0b1d86a3634b34b5fe8222c1442290f9ba55931a9a891f45790b01b6eaae4131ccf22ba81eecc0053dc059de8fb020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "mtp": {
                    "existence": true,
                    "siblings": []
                },
                "credentialStatus": {
                    "id": "https://ad40-91-210-251-7.ngrok-free.app/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qFdiASbojMMsUzEo3Qg7pbhoD52hfm2qDJmtbRgQU/claims/revocation/status/0",
                    "revocationNonce": 0,
                    "type": "SparseMerkleTreeProof"
                }
            },
            "coreClaim": "cb373906ed88fff9332f71521b712c950a0000000000000000000000000000000212620a53d8184c2ae591951aa8e3f3e1fcd48ea329b858cf5c762d22e70d006892300100000000000000000000000000000000000000000000000000000000630000000000000000000000000000000000000000000000000000000000000014fc885300000000281cdcdf0200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "signature": "1dd9f4da6b5595e6440b986f726644e5cf0148d8b62416e46001d55edd56d88bde86e8f5232a0171076f3d1e570ea6210b26b60ed3087a6b778735ee03946205"
        },
        {
            "type": "Iden3SparseMerkleTreeProof",
            "issuerData": {
                "id": "did:polygonid:polygon:mumbai:2qFdiASbojMMsUzEo3Qg7pbhoD52hfm2qDJmtbRgQU",
                "state": {
                    "txId": "0x60d8aedaf8a36b99b75a9d5f4f324e297971d082d566e6e76b2e2cd8db4e7581",
                    "blockTimestamp": 1703087558,
                    "blockNumber": 43801486,
                    "rootOfRoots": "d58fceb8f0876e19f503eec399d2d58c27db9289275b8380b1569d5415a09f10",
                    "claimsTreeRoot": "f5d12ddeaa78a14b747affd90296838bd843e472d8ca1d22823eff54a928aa04",
                    "revocationTreeRoot": "0000000000000000000000000000000000000000000000000000000000000000",
                    "value": "f23e90dea7b2f751025270ef7ecccbcb00d4b5e52a736baeeb6ea67b461ad815"
                }
            },
            "coreClaim": "cb373906ed88fff9332f71521b712c950a0000000000000000000000000000000212620a53d8184c2ae591951aa8e3f3e1fcd48ea329b858cf5c762d22e70d006892300100000000000000000000000000000000000000000000000000000000630000000000000000000000000000000000000000000000000000000000000014fc885300000000281cdcdf0200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "mtp": {
                "existence": true,
                "siblings": [
                    "0",
                    "0",
                    "0",
                    "9034962096517585342502758427391496503570392048063319342760007271811456764196"
                ]
            }
        }
    ]
}`
	var vc W3CCredential
	err := json.Unmarshal([]byte(in), &vc)

	isValid, err := vc.ValidateProof(context.Background(), Iden3SparseMerkleTreeProofType)
	require.NoError(t, err)
	require.True(t, isValid)
}

func TestW3CCredential_JSONUnmarshal(t *testing.T) {
	in := `{
    "id": "http://ec2-34-247-165-109.eu-west-1.compute.amazonaws.com:8888/api/v1/claim/52cec4e3-7d1d-11ed-ade2-0242ac180007",
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld",
      "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld"
    ],
    "type": [
      "VerifiableCredential",
      "KYCAgeCredential"
    ],
    "expirationDate": "2361-03-21T19:14:48Z",
    "issuanceDate": "2022-12-16T08:40:41.515927692Z",
    "credentialSubject": {
      "birthday": 19960424,
      "documentType": 2,
      "id": "did:iden3:polygon:mumbai:x3YTKSK1fWBbQAmMhArxvFBcG8tL7m2ZMFh5LSyjH",
      "type": "KYCAgeCredential"
    },
    "credentialStatus": {
      "id": "http://ec2-34-247-165-109.eu-west-1.compute.amazonaws.com:8888/api/v1/identities/did%3Aiden3%3Apolygon%3Amumbai%3AwvEkzpApgwGHrSTxEFG6V6HrTCa5R2rwQ3XWAkrnG/claims/revocation/status/1529060834",
      "revocationNonce": 1529060834,
      "type": "SparseMerkleTreeProof"
    },
    "issuer": "did:iden3:polygon:mumbai:wvEkzpApgwGHrSTxEFG6V6HrTCa5R2rwQ3XWAkrnG",
    "credentialSchema": {
      "id": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/KYCAgeCredential-v3.json",
      "type": "JsonSchemaValidator2018"
    },
    "proof": [
      {
        "type": "BJJSignature2021",
        "issuerData": {
          "id": "did:iden3:polygon:mumbai:wvEkzpApgwGHrSTxEFG6V6HrTCa5R2rwQ3XWAkrnG",
          "state": {
            "claimsTreeRoot": "93121670a2a82d42adb3eae22d609c2495ee675d36feaaef75bd030b3e98f621",
            "value": "fab7bdf8551406b0bc2df0dabf811449d74628f02e98b2e4ea02f01b996a4e05"
          },
          "authCoreClaim": "013fd3f623559d850fb5b02ff012d0e20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001409ffecd5566451e39ee1cf7ff2e5b369ef6a708e51f80d7ba282e5c1f6d80eb88eb6df418a768c1f9dc4cc1c6109564f6d5a36d74a7085d9f90c66ae03641c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
          "mtp": {
            "existence": true,
            "siblings": []
          },
          "credentialStatus": {
            "id": "http://ec2-34-247-165-109.eu-west-1.compute.amazonaws.com:8888/api/v1/identities/did%3Aiden3%3Apolygon%3Amumbai%3AwvEkzpApgwGHrSTxEFG6V6HrTCa5R2rwQ3XWAkrnG/claims/revocation/status/0",
            "revocationNonce": 0,
            "type": "SparseMerkleTreeProof"
          }
        },
        "coreClaim": "c9b2370371b7fa8b3dab2a5ba81b68382a0000000000000000000000000000000112b4f1183b6a0708a8addd31c093004ac2e40ab1b291ad6d208244032b0c006947c37450a6a4c50a586e8a253dc8385d8d1ee77b37f464fe5052dc2f0dd8020000000000000000000000000000000000000000000000000000000000000000e29d235b00000000281cdcdf0200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "signature": "b36ed82e13d2868d6b5c5dff0f461e309e1af4cf3fdc9822fd0f86b76c820f19cd728d06ff22c259d4aeef3406c3d44577014fbd0e8fb14330022de77bda8302"
      },
      {
        "type": "Iden3SparseMerkleProof",
        "issuerData": {
          "id": "did:iden3:polygon:mumbai:wvEkzpApgwGHrSTxEFG6V6HrTCa5R2rwQ3XWAkrnG",
          "state": {
            "txId": "0x705881f799496f399321f7b3b0f9aab80e358e5fdacb877ef18f10afc8be156e",
            "blockTimestamp": 1671180108,
            "blockNumber": 29756768,
            "rootOfRoots": "db07217f60526821e8c079802ebfbfb9cd07e42d4220ff72f264d9bddbe87d2f",
            "claimsTreeRoot": "447b1dfd065752d099c4c8eeb181dfe1363c64491eb413f01d6e60daf6bc792e",
            "revocationTreeRoot": "0000000000000000000000000000000000000000000000000000000000000000",
            "value": "0bc71a0bdbf1a3e8513069b170c6b62601288fcf231f874b52e4e546dddcbb2d"
          }
        },
        "coreClaim": "c9b2370371b7fa8b3dab2a5ba81b68382a0000000000000000000000000000000112b4f1183b6a0708a8addd31c093004ac2e40ab1b291ad6d208244032b0c006947c37450a6a4c50a586e8a253dc8385d8d1ee77b37f464fe5052dc2f0dd8020000000000000000000000000000000000000000000000000000000000000000e29d235b00000000281cdcdf0200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "mtp": {
          "existence": true,
          "siblings": [
            "0",
            "13291429422163653257975736723599735973011351095941906941706092370486076739639",
            "13426716414767621234869633661856285788095461522423569801792562280466318278688"
          ]
        }
      }
    ]
  }`
	var vc W3CCredential
	err := json.Unmarshal([]byte(in), &vc)
	require.NoError(t, err)

	want := W3CCredential{
		ID: "http://ec2-34-247-165-109.eu-west-1.compute.amazonaws.com:8888/api/v1/claim/52cec4e3-7d1d-11ed-ade2-0242ac180007",
		Context: []string{
			"https://www.w3.org/2018/credentials/v1",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
		},
		Type: []string{
			"VerifiableCredential",
			"KYCAgeCredential",
		},
		Expiration: &[]time.Time{
			time.Date(2361, 3, 21, 19, 14, 48, 0, time.UTC)}[0],
		IssuanceDate: &[]time.Time{
			time.Date(2022, 12, 16, 8, 40, 41, 515927692, time.UTC)}[0],
		CredentialSubject: map[string]any{
			"birthday":     float64(19960424),
			"documentType": float64(2),
			"id":           "did:iden3:polygon:mumbai:x3YTKSK1fWBbQAmMhArxvFBcG8tL7m2ZMFh5LSyjH",
			"type":         "KYCAgeCredential",
		},
		CredentialStatus: map[string]any{
			"id":              "http://ec2-34-247-165-109.eu-west-1.compute.amazonaws.com:8888/api/v1/identities/did%3Aiden3%3Apolygon%3Amumbai%3AwvEkzpApgwGHrSTxEFG6V6HrTCa5R2rwQ3XWAkrnG/claims/revocation/status/1529060834",
			"revocationNonce": float64(1529060834),
			"type":            "SparseMerkleTreeProof",
		},
		Issuer: "did:iden3:polygon:mumbai:wvEkzpApgwGHrSTxEFG6V6HrTCa5R2rwQ3XWAkrnG",
		CredentialSchema: CredentialSchema{
			ID:   "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/KYCAgeCredential-v3.json",
			Type: "JsonSchemaValidator2018",
		},
		Proof: CredentialProofs{
			&BJJSignatureProof2021{
				Type: BJJSignatureProofType,
				IssuerData: IssuerData{
					ID: "did:iden3:polygon:mumbai:wvEkzpApgwGHrSTxEFG6V6HrTCa5R2rwQ3XWAkrnG",
					State: State{
						ClaimsTreeRoot: &[]string{"93121670a2a82d42adb3eae22d609c2495ee675d36feaaef75bd030b3e98f621"}[0],
						Value:          &[]string{"fab7bdf8551406b0bc2df0dabf811449d74628f02e98b2e4ea02f01b996a4e05"}[0],
					},
					AuthCoreClaim: "013fd3f623559d850fb5b02ff012d0e20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001409ffecd5566451e39ee1cf7ff2e5b369ef6a708e51f80d7ba282e5c1f6d80eb88eb6df418a768c1f9dc4cc1c6109564f6d5a36d74a7085d9f90c66ae03641c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
					MTP:           mustProof(t, true, []*mt.Hash{}),
					CredentialStatus: map[string]interface{}{
						"id":              "http://ec2-34-247-165-109.eu-west-1.compute.amazonaws.com:8888/api/v1/identities/did%3Aiden3%3Apolygon%3Amumbai%3AwvEkzpApgwGHrSTxEFG6V6HrTCa5R2rwQ3XWAkrnG/claims/revocation/status/0",
						"revocationNonce": float64(0),
						"type":            "SparseMerkleTreeProof",
					},
				},
				CoreClaim: "c9b2370371b7fa8b3dab2a5ba81b68382a0000000000000000000000000000000112b4f1183b6a0708a8addd31c093004ac2e40ab1b291ad6d208244032b0c006947c37450a6a4c50a586e8a253dc8385d8d1ee77b37f464fe5052dc2f0dd8020000000000000000000000000000000000000000000000000000000000000000e29d235b00000000281cdcdf0200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
				Signature: "b36ed82e13d2868d6b5c5dff0f461e309e1af4cf3fdc9822fd0f86b76c820f19cd728d06ff22c259d4aeef3406c3d44577014fbd0e8fb14330022de77bda8302",
			},
			&Iden3SparseMerkleProof{
				Type: Iden3SparseMerkleProofType,
				IssuerData: IssuerData{
					ID: "did:iden3:polygon:mumbai:wvEkzpApgwGHrSTxEFG6V6HrTCa5R2rwQ3XWAkrnG",
					State: State{
						TxID:               &[]string{"0x705881f799496f399321f7b3b0f9aab80e358e5fdacb877ef18f10afc8be156e"}[0],
						BlockTimestamp:     &[]int{1671180108}[0],
						BlockNumber:        &[]int{29756768}[0],
						RootOfRoots:        &[]string{"db07217f60526821e8c079802ebfbfb9cd07e42d4220ff72f264d9bddbe87d2f"}[0],
						ClaimsTreeRoot:     &[]string{"447b1dfd065752d099c4c8eeb181dfe1363c64491eb413f01d6e60daf6bc792e"}[0],
						RevocationTreeRoot: &[]string{"0000000000000000000000000000000000000000000000000000000000000000"}[0],
						Value:              &[]string{"0bc71a0bdbf1a3e8513069b170c6b62601288fcf231f874b52e4e546dddcbb2d"}[0],
						Status:             "",
					},
					AuthCoreClaim:    "",
					MTP:              nil,
					CredentialStatus: nil,
				},
				CoreClaim: "c9b2370371b7fa8b3dab2a5ba81b68382a0000000000000000000000000000000112b4f1183b6a0708a8addd31c093004ac2e40ab1b291ad6d208244032b0c006947c37450a6a4c50a586e8a253dc8385d8d1ee77b37f464fe5052dc2f0dd8020000000000000000000000000000000000000000000000000000000000000000e29d235b00000000281cdcdf0200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
				MTP: mustProof(t, true, []*mt.Hash{
					mustHash(t, "0"),
					mustHash(t,
						"13291429422163653257975736723599735973011351095941906941706092370486076739639"),
					mustHash(t,
						"13426716414767621234869633661856285788095461522423569801792562280466318278688"),
				}),
			},
		},
	}
	require.Equal(t, want, vc)
}

func TestW3CCredential_MerklizationWithEmptyID(t *testing.T) {
	defer tst.MockHTTPClient(t, map[string]string{
		"https://www.w3.org/2018/credentials/v1":              "../merklize/testdata/httpresp/credentials-v1.jsonld",
		"https://example.com/schema-delivery-address.json-ld": "../json/testdata/schema-delivery-address.json-ld",
	})()

	vcData, err := os.ReadFile("../json/testdata/non-merklized-1.json-ld")
	require.NoError(t, err)
	var vc W3CCredential
	err = json.Unmarshal(vcData, &vc)
	require.NoError(t, err)

	want := W3CCredential{
		ID: "",
		Context: []string{
			"https://www.w3.org/2018/credentials/v1",
			"https://example.com/schema-delivery-address.json-ld",
		},
		Type: []string{
			"VerifiableCredential",
			"DeliverAddressMultiTestForked",
		},
		CredentialSubject: map[string]any{
			"type":             "DeliverAddressMultiTestForked",
			"price":            "123.52",
			"isPostalProvider": false,
			"postalProviderInformation": map[string]any{
				"insured": true,
				"weight":  "1.3",
			},
		},
		CredentialStatus: nil,
		Issuer:           "",
		CredentialSchema: CredentialSchema{
			ID:   "",
			Type: "",
		},
	}
	require.Equal(t, want, vc)

	ctx := context.Background()
	mz, err := vc.Merklize(ctx)
	require.NoError(t, err)
	path, err := mz.ResolveDocPath("credentialSubject.price")
	require.NoError(t, err)
	_, err = mz.Entry(path)
	require.NoError(t, err)
}
