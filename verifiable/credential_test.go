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

type test1Resolver struct{}

func (test1Resolver) Resolve(context context.Context, status CredentialStatus) (out RevocationStatus, err error) {
	statusJSON := `{"issuer":{"state":"34824a8e1defc326f935044e32e9f513377dbfc031d79475a0190830554d4409","rootOfRoots":"37eabc712cdaa64793561b16b8143f56f149ad1b0c35297a1b125c765d1c071e","claimsTreeRoot":"4436ea12d352ddb84d2ac7a27bbf7c9f1bfc7d3ff69f3e6cf4348f424317fd0b","revocationTreeRoot":"0000000000000000000000000000000000000000000000000000000000000000"},"mtp":{"existence":false,"siblings":[]}}`
	var rs RevocationStatus
	_ = json.Unmarshal([]byte(statusJSON), &rs)
	return rs, nil
}
func TestW3CCredential_ValidateBJJSignatureProof(t *testing.T) {
	in := `{
    "id": "urn:uuid:3a8d1822-a00e-11ee-8f57-a27b3ddbdc29",
    "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://schema.iden3.io/core/jsonld/iden3proofs.jsonld",
        "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld"
    ],
    "type": [
        "VerifiableCredential",
        "KYCAgeCredential"
    ],
    "expirationDate": "2361-03-21T21:14:48+02:00",
    "issuanceDate": "2023-12-21T16:35:46.737547+02:00",
    "credentialSubject": {
        "birthday": 19960424,
        "documentType": 2,
        "id": "did:polygonid:polygon:mumbai:2qH2mPVRN7ZDCnEofjeh8Qd2Uo3YsEhTVhKhjB8xs4",
        "type": "KYCAgeCredential"
    },
    "credentialStatus": {
        "id": "https://rhs-staging.polygonid.me/node?state=f9dd6aa4e1abef52b6c94ab7eb92faf1a283b371d263e25ac835c9c04894741e",
        "revocationNonce": 74881362,
        "statusIssuer": {
            "id": "https://ad40-91-210-251-7.ngrok-free.app/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qLGnFZiHrhdNh5KwdkGvbCN1sR2pUaBpBahAXC3zf/claims/revocation/status/74881362",
            "revocationNonce": 74881362,
            "type": "SparseMerkleTreeProof"
        },
        "type": "Iden3ReverseSparseMerkleTreeProof"
    },
    "issuer": "did:polygonid:polygon:mumbai:2qLGnFZiHrhdNh5KwdkGvbCN1sR2pUaBpBahAXC3zf",
    "credentialSchema": {
        "id": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/KYCAgeCredential-v3.json",
        "type": "JsonSchema2023"
    },
    "proof": [
        {
            "type": "BJJSignature2021",
            "issuerData": {
                "id": "did:polygonid:polygon:mumbai:2qLGnFZiHrhdNh5KwdkGvbCN1sR2pUaBpBahAXC3zf",
                "state": {
                    "claimsTreeRoot": "d946e9cb604bceb0721e4548c291b013647eb56a2cd755b965e6c3b840026517",
                    "value": "f9dd6aa4e1abef52b6c94ab7eb92faf1a283b371d263e25ac835c9c04894741e"
                },
                "authCoreClaim": "cca3371a6cb1b715004407e325bd993c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000d7d1691a4202c0a1e580da2a87118c26a399849c42e52c4d97506a5bf5985923e6ec8ef6caeb482daa0d7516a864ace8fba2854275781583934349b51ba70c190000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "mtp": {
                    "existence": true,
                    "siblings": []
                },
                "credentialStatus": {
                    "id": "https://rhs-staging.polygonid.me/node?state=f9dd6aa4e1abef52b6c94ab7eb92faf1a283b371d263e25ac835c9c04894741e",
                    "revocationNonce": 0,
                    "statusIssuer": {
                        "id": "https://ad40-91-210-251-7.ngrok-free.app/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qLGnFZiHrhdNh5KwdkGvbCN1sR2pUaBpBahAXC3zf/claims/revocation/status/0",
                        "revocationNonce": 0,
                        "type": "SparseMerkleTreeProof"
                    },
                    "type": "Iden3ReverseSparseMerkleTreeProof"
                }
            },
            "coreClaim": "c9b2370371b7fa8b3dab2a5ba81b68382a000000000000000000000000000000021264874acc807e8862077487500a0e9b550a84d667348fc936a4dd0e730b00d4bfb0b3fc0b67c4437ee22848e5de1a7a71748c428358625a5fbac1cebf982000000000000000000000000000000000000000000000000000000000000000005299760400000000281cdcdf0200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "signature": "1783ff1c8207d3047a2ba6baa341dc8a6cb095e5683c6fb619ba4099d3332d2b209dca0a0676e41d4675154ea07662c7d9e14a7ee57259f85f3596493ac71a01"
        }
    ]
}`
	var vc W3CCredential
	err := json.Unmarshal([]byte(in), &vc)
	require.NoError(t, err)

	resolverURL := "http://my-universal-resolver/1.0/identifiers"

	defer tst.MockHTTPClient(t,
		map[string]string{
			"http://my-universal-resolver/1.0/identifiers/did%3Apolygonid%3Apolygon%3Amumbai%3A2qLGnFZiHrhdNh5KwdkGvbCN1sR2pUaBpBahAXC3zf?state=f9dd6aa4e1abef52b6c94ab7eb92faf1a283b371d263e25ac835c9c04894741e": `./testdata/verifycred//my-universal-resolver-1.json`,
		})()
	resolverRegisty := CredentialStatusResolverRegistry{}
	rhsResolver := test1Resolver{}
	resolverRegisty.Register(Iden3ReverseSparseMerkleTreeProof, rhsResolver)
	verifyConfig := []W3CProofVerificationOpt{WithStatusResolverRegistry(&resolverRegisty)}
	err = vc.VerifyProof(context.Background(), BJJSignatureProofType,
		HTTPDIDResolver{resolverURL: resolverURL}, verifyConfig...)
	require.NoError(t, err)
}

type test2Resolver struct{}

func (test2Resolver) Resolve(context context.Context, status CredentialStatus) (out RevocationStatus, err error) {
	statusJSON := `{"issuer":{"state":"da6184809dbad90ccc52bb4dbfe2e8ff3f516d87c74d75bcc68a67101760b817","rootOfRoots":"0000000000000000000000000000000000000000000000000000000000000000","claimsTreeRoot":"aec50251fdc67959254c74ab4f2e746a7cd1c6f494c8ac028d655dfbccea430e","revocationTreeRoot":"0000000000000000000000000000000000000000000000000000000000000000"},"mtp":{"existence":false,"siblings":[]}}`
	var rs RevocationStatus
	_ = json.Unmarshal([]byte(statusJSON), &rs)
	return rs, nil
}
func TestW3CCredential_ValidateBJJSignatureProofGenesis(t *testing.T) {
	in := `{
    "id": "urn:uuid:b7a1e232-a0d3-11ee-bc8a-a27b3ddbdc29",
    "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://schema.iden3.io/core/jsonld/iden3proofs.jsonld",
        "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld"
    ],
    "type": [
        "VerifiableCredential",
        "KYCAgeCredential"
    ],
    "expirationDate": "2361-03-21T21:14:48+02:00",
    "issuanceDate": "2023-12-22T16:09:27.444712+02:00",
    "credentialSubject": {
        "birthday": 19960424,
        "documentType": 2,
        "id": "did:polygonid:polygon:mumbai:2qJm6vBXtHWMqm9A9f5zihRNVGptHAHcK8oVxGUTg8",
        "type": "KYCAgeCredential"
    },
    "credentialStatus": {
        "id": "https://rhs-staging.polygonid.me/node?state=da6184809dbad90ccc52bb4dbfe2e8ff3f516d87c74d75bcc68a67101760b817",
        "revocationNonce": 1102174849,
        "statusIssuer": {
            "id": "https://ad40-91-210-251-7.ngrok-free.app/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qLx3hTJBV8REpNDK2RiG7eNBVzXMoZdPfi2uhF7Ks/claims/revocation/status/1102174849",
            "revocationNonce": 1102174849,
            "type": "SparseMerkleTreeProof"
        },
        "type": "Iden3ReverseSparseMerkleTreeProof"
    },
    "issuer": "did:polygonid:polygon:mumbai:2qLx3hTJBV8REpNDK2RiG7eNBVzXMoZdPfi2uhF7Ks",
    "credentialSchema": {
        "id": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/KYCAgeCredential-v3.json",
        "type": "JsonSchema2023"
    },
    "proof": [
        {
            "type": "BJJSignature2021",
            "issuerData": {
                "id": "did:polygonid:polygon:mumbai:2qLx3hTJBV8REpNDK2RiG7eNBVzXMoZdPfi2uhF7Ks",
                "state": {
                    "claimsTreeRoot": "aec50251fdc67959254c74ab4f2e746a7cd1c6f494c8ac028d655dfbccea430e",
                    "value": "da6184809dbad90ccc52bb4dbfe2e8ff3f516d87c74d75bcc68a67101760b817"
                },
                "authCoreClaim": "cca3371a6cb1b715004407e325bd993c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c08ac5cc7c5aa3e8190e188cf8d1737c92d16188541b582ef676c55b3a842c06c4985e9d4771ee6d033c2021a3d177f7dfa51859d99a9a476c2a910e887dc8240000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "mtp": {
                    "existence": true,
                    "siblings": []
                },
                "credentialStatus": {
                    "id": "https://rhs-staging.polygonid.me/node?state=da6184809dbad90ccc52bb4dbfe2e8ff3f516d87c74d75bcc68a67101760b817",
                    "revocationNonce": 0,
                    "statusIssuer": {
                        "id": "https://ad40-91-210-251-7.ngrok-free.app/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qLx3hTJBV8REpNDK2RiG7eNBVzXMoZdPfi2uhF7Ks/claims/revocation/status/0",
                        "revocationNonce": 0,
                        "type": "SparseMerkleTreeProof"
                    },
                    "type": "Iden3ReverseSparseMerkleTreeProof"
                }
            },
            "coreClaim": "c9b2370371b7fa8b3dab2a5ba81b68382a00000000000000000000000000000002128aa2ae20d4f8f7b9d673e06498fa410f3c5a790194f3b9284a2018f30d0037d1e542f1b72c9d5ca4b46d93710fbfa23a7c9c36eb3ca0eb0f9548ad9c140c000000000000000000000000000000000000000000000000000000000000000081dab14100000000281cdcdf0200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "signature": "2a2e4d79f3aa440154643252d1b9074f9651fffcd653fb2fcadc07f55cd1f9a20a812dd7df8ba8775653984cfb7120f999751f9c25473fd634c7f2d88419c102"
        }
    ]
}`
	var vc W3CCredential
	err := json.Unmarshal([]byte(in), &vc)
	require.NoError(t, err)

	resolverURL := "http://my-universal-resolver/1.0/identifiers"

	defer tst.MockHTTPClient(t,
		map[string]string{
			"http://my-universal-resolver/1.0/identifiers/did%3Apolygonid%3Apolygon%3Amumbai%3A2qLx3hTJBV8REpNDK2RiG7eNBVzXMoZdPfi2uhF7Ks?state=da6184809dbad90ccc52bb4dbfe2e8ff3f516d87c74d75bcc68a67101760b817": `./testdata/verifycred//my-universal-resolver-2.json`,
		})()

	resolverRegisty := CredentialStatusResolverRegistry{}
	rhsResolver := test2Resolver{}
	resolverRegisty.Register(Iden3ReverseSparseMerkleTreeProof, rhsResolver)
	verifyConfig := []W3CProofVerificationOpt{WithStatusResolverRegistry(&resolverRegisty)}

	err = vc.VerifyProof(context.Background(), BJJSignatureProofType,
		HTTPDIDResolver{resolverURL: resolverURL}, verifyConfig...)
	require.NoError(t, err)
}

func TestW3CCredential_ValidateIden3SparseMerkleTreeProof(t *testing.T) {
	in := `{
    "id": "urn:uuid:3a8d1822-a00e-11ee-8f57-a27b3ddbdc29",
    "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://schema.iden3.io/core/jsonld/iden3proofs.jsonld",
        "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld"
    ],
    "type": [
        "VerifiableCredential",
        "KYCAgeCredential"
    ],
    "expirationDate": "2361-03-21T21:14:48+02:00",
    "issuanceDate": "2023-12-21T16:35:46.737547+02:00",
    "credentialSubject": {
        "birthday": 19960424,
        "documentType": 2,
        "id": "did:polygonid:polygon:mumbai:2qH2mPVRN7ZDCnEofjeh8Qd2Uo3YsEhTVhKhjB8xs4",
        "type": "KYCAgeCredential"
    },
    "credentialStatus": {
        "id": "https://rhs-staging.polygonid.me/node?state=f9dd6aa4e1abef52b6c94ab7eb92faf1a283b371d263e25ac835c9c04894741e",
        "revocationNonce": 74881362,
        "statusIssuer": {
            "id": "https://ad40-91-210-251-7.ngrok-free.app/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qLGnFZiHrhdNh5KwdkGvbCN1sR2pUaBpBahAXC3zf/claims/revocation/status/74881362",
            "revocationNonce": 74881362,
            "type": "SparseMerkleTreeProof"
        },
        "type": "Iden3ReverseSparseMerkleTreeProof"
    },
    "issuer": "did:polygonid:polygon:mumbai:2qLGnFZiHrhdNh5KwdkGvbCN1sR2pUaBpBahAXC3zf",
    "credentialSchema": {
        "id": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/KYCAgeCredential-v3.json",
        "type": "JsonSchema2023"
    },
    "proof": [
        {
            "type": "BJJSignature2021",
            "issuerData": {
                "id": "did:polygonid:polygon:mumbai:2qLGnFZiHrhdNh5KwdkGvbCN1sR2pUaBpBahAXC3zf",
                "state": {
                    "claimsTreeRoot": "d946e9cb604bceb0721e4548c291b013647eb56a2cd755b965e6c3b840026517",
                    "value": "f9dd6aa4e1abef52b6c94ab7eb92faf1a283b371d263e25ac835c9c04894741e"
                },
                "authCoreClaim": "cca3371a6cb1b715004407e325bd993c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000d7d1691a4202c0a1e580da2a87118c26a399849c42e52c4d97506a5bf5985923e6ec8ef6caeb482daa0d7516a864ace8fba2854275781583934349b51ba70c190000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "mtp": {
                    "existence": true,
                    "siblings": []
                },
                "credentialStatus": {
                    "id": "https://rhs-staging.polygonid.me/node?state=f9dd6aa4e1abef52b6c94ab7eb92faf1a283b371d263e25ac835c9c04894741e",
                    "revocationNonce": 0,
                    "statusIssuer": {
                        "id": "https://ad40-91-210-251-7.ngrok-free.app/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qLGnFZiHrhdNh5KwdkGvbCN1sR2pUaBpBahAXC3zf/claims/revocation/status/0",
                        "revocationNonce": 0,
                        "type": "SparseMerkleTreeProof"
                    },
                    "type": "Iden3ReverseSparseMerkleTreeProof"
                }
            },
            "coreClaim": "c9b2370371b7fa8b3dab2a5ba81b68382a000000000000000000000000000000021264874acc807e8862077487500a0e9b550a84d667348fc936a4dd0e730b00d4bfb0b3fc0b67c4437ee22848e5de1a7a71748c428358625a5fbac1cebf982000000000000000000000000000000000000000000000000000000000000000005299760400000000281cdcdf0200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "signature": "1783ff1c8207d3047a2ba6baa341dc8a6cb095e5683c6fb619ba4099d3332d2b209dca0a0676e41d4675154ea07662c7d9e14a7ee57259f85f3596493ac71a01"
        },
        {
            "type": "Iden3SparseMerkleTreeProof",
            "issuerData": {
                "id": "did:polygonid:polygon:mumbai:2qLGnFZiHrhdNh5KwdkGvbCN1sR2pUaBpBahAXC3zf",
                "state": {
                    "txId": "0x7ab71a8c5e91064e21beb586012f8b89932c255e243c496dec895a501a42e243",
                    "blockTimestamp": 1703174663,
                    "blockNumber": 43840767,
                    "rootOfRoots": "37eabc712cdaa64793561b16b8143f56f149ad1b0c35297a1b125c765d1c071e",
                    "claimsTreeRoot": "4436ea12d352ddb84d2ac7a27bbf7c9f1bfc7d3ff69f3e6cf4348f424317fd0b",
                    "revocationTreeRoot": "0000000000000000000000000000000000000000000000000000000000000000",
                    "value": "34824a8e1defc326f935044e32e9f513377dbfc031d79475a0190830554d4409"
                }
            },
            "coreClaim": "c9b2370371b7fa8b3dab2a5ba81b68382a000000000000000000000000000000021264874acc807e8862077487500a0e9b550a84d667348fc936a4dd0e730b00d4bfb0b3fc0b67c4437ee22848e5de1a7a71748c428358625a5fbac1cebf982000000000000000000000000000000000000000000000000000000000000000005299760400000000281cdcdf0200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "mtp": {
                "existence": true,
                "siblings": [
                    "0",
                    "10581662619345074277108685138429405012286849178024033034405862946888154171097"
                ]
            }
        }
    ]
}`
	var vc W3CCredential
	err := json.Unmarshal([]byte(in), &vc)
	require.NoError(t, err)

	resolverURL := "http://my-universal-resolver/1.0/identifiers"

	defer tst.MockHTTPClient(t,
		map[string]string{
			"http://my-universal-resolver/1.0/identifiers/did%3Apolygonid%3Apolygon%3Amumbai%3A2qLGnFZiHrhdNh5KwdkGvbCN1sR2pUaBpBahAXC3zf?state=34824a8e1defc326f935044e32e9f513377dbfc031d79475a0190830554d4409": `./testdata/verifycred//my-universal-resolver-3.json`,
		})()

	err = vc.VerifyProof(context.Background(), Iden3SparseMerkleTreeProofType,
		HTTPDIDResolver{resolverURL: resolverURL})
	require.NoError(t, err)
}

type test3Resolver struct{}

func (test3Resolver) Resolve(context context.Context, status CredentialStatus) (out RevocationStatus, err error) {
	statusJSON := `{"issuer":{"state":"96161f3fbbdd68c72bc430dae474e27b157586b33b9fbf4a3f07d75ce275570f","rootOfRoots":"eaa48e4a7d3fe2fabbd939c7df1048c3f647a9a7c9dfadaae836ec78ba673229","claimsTreeRoot":"d9597e2fef206c9821f2425e513a68c8c793bc93c9216fb883fedaaf72abf51c","revocationTreeRoot":"0000000000000000000000000000000000000000000000000000000000000000"},"mtp":{"existence":false,"siblings":[]}}`
	var rs RevocationStatus
	_ = json.Unmarshal([]byte(statusJSON), &rs)
	return rs, nil
}

func TestW3CCredential_ValidateBJJSignatureProofAgentStatus(t *testing.T) {
	in := `{
        "id": "urn:uuid:79d93584-ae2c-11ee-8050-a27b3ddbdc28",
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://schema.iden3.io/core/jsonld/iden3proofs.jsonld",
            "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld"
        ],
        "type": [
            "VerifiableCredential",
            "KYCAgeCredential"
        ],
        "expirationDate": "2361-03-21T21:14:48+02:00",
        "issuanceDate": "2024-01-08T15:47:34.113565+02:00",
        "credentialSubject": {
            "birthday": 19960424,
            "documentType": 2,
            "id": "did:polygonid:polygon:mumbai:2qFDziX3k3h7To2jDJbQiXFtcozbgSNNvQpb6TgtPE",
            "type": "KYCAgeCredential"
        },
        "credentialStatus": {
            "id": "http://localhost:8001/api/v1/agent",
            "revocationNonce": 3262660310,
            "type": "Iden3commRevocationStatusV1.0"
        },
        "issuer": "did:polygonid:polygon:mumbai:2qJp131YoXVu8iLNGfL3TkQAWEr3pqimh2iaPgH3BJ",
        "credentialSchema": {
            "id": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/KYCAgeCredential-v3.json",
            "type": "JsonSchema2023"
        },
        "proof": [
            {
                "type": "BJJSignature2021",
                "issuerData": {
                    "id": "did:polygonid:polygon:mumbai:2qJp131YoXVu8iLNGfL3TkQAWEr3pqimh2iaPgH3BJ",
                    "state": {
                        "claimsTreeRoot": "b35562873d9870f20e3d44dd94502f4156785a4b09d7906914758a7e0ed26829",
                        "value": "2de39210318bbc7fc79e24150c2790089c8385d7acffc0f0ebf1641b95087e0f"
                    },
                    "authCoreClaim": "cca3371a6cb1b715004407e325bd993c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000167c1d2857ca6579d6e995198876cdfd4edb4fe2eeedeadbabaaed3008225205e7b8ab88a60b9ef0999be82625e0831872d8aca16b2932852c3731e9df69970a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                    "mtp": {
                        "existence": true,
                        "siblings": []
                    },
                    "credentialStatus": {
                        "id": "http://localhost:8001/api/v1/agent",
                        "revocationNonce": 0,
                        "type": "Iden3commRevocationStatusV1.0"
                    }
                },
                "coreClaim": "c9b2370371b7fa8b3dab2a5ba81b68382a00000000000000000000000000000002123cbcd9d0f3a493561510c72b47afcb02e2f09b3855291c6b77d224260d0014f503c3ab03eebe757d5b50b570186a69d90c49904155f5fc71e0e7f5b8aa120000000000000000000000000000000000000000000000000000000000000000d63e78c200000000281cdcdf0200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "signature": "56ab45ad828c4860d02e111b2732c969005046ee26dbc7d1e5bd6a6c6604ed81c3f55ffb9349f4d407f59e2e210f6d256a328d30edae2c7c95dd057240ee8902"
            },
            {
                "type": "Iden3SparseMerkleTreeProof",
                "issuerData": {
                    "id": "did:polygonid:polygon:mumbai:2qJp131YoXVu8iLNGfL3TkQAWEr3pqimh2iaPgH3BJ",
                    "state": {
                        "txId": "0x02f1af6a616715ccb7511176ca53d39a28c55201effca0b43a343ee6e9dc8c97",
                        "blockTimestamp": 1704721690,
                        "blockNumber": 44542683,
                        "rootOfRoots": "eaa48e4a7d3fe2fabbd939c7df1048c3f647a9a7c9dfadaae836ec78ba673229",
                        "claimsTreeRoot": "d9597e2fef206c9821f2425e513a68c8c793bc93c9216fb883fedaaf72abf51c",
                        "revocationTreeRoot": "0000000000000000000000000000000000000000000000000000000000000000",
                        "value": "96161f3fbbdd68c72bc430dae474e27b157586b33b9fbf4a3f07d75ce275570f"
                    }
                },
                "coreClaim": "c9b2370371b7fa8b3dab2a5ba81b68382a00000000000000000000000000000002123cbcd9d0f3a493561510c72b47afcb02e2f09b3855291c6b77d224260d0014f503c3ab03eebe757d5b50b570186a69d90c49904155f5fc71e0e7f5b8aa120000000000000000000000000000000000000000000000000000000000000000d63e78c200000000281cdcdf0200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "mtp": {
                    "existence": true,
                    "siblings": [
                        "18730028644149260049434737497088408840959357817865392043806470281178241979827"
                    ]
                }
            }
        ]
    }`
	var vc W3CCredential
	err := json.Unmarshal([]byte(in), &vc)
	require.NoError(t, err)

	resolverURL := "http://my-universal-resolver/1.0/identifiers"

	defer tst.MockHTTPClient(t,
		map[string]string{
			"http://my-universal-resolver/1.0/identifiers/did%3Apolygonid%3Apolygon%3Amumbai%3A2qJp131YoXVu8iLNGfL3TkQAWEr3pqimh2iaPgH3BJ?state=2de39210318bbc7fc79e24150c2790089c8385d7acffc0f0ebf1641b95087e0f": `./testdata/verifycred//my-universal-resolver-4.json`,
		})()

	resolverRegisty := CredentialStatusResolverRegistry{}
	resolverRegisty.Register(Iden3commRevocationStatusV1, test3Resolver{})
	verifyConfig := []W3CProofVerificationOpt{WithStatusResolverRegistry(&resolverRegisty)}
	err = vc.VerifyProof(context.Background(), BJJSignatureProofType, HTTPDIDResolver{resolverURL: resolverURL},
		verifyConfig...)
	require.NoError(t, err)
}

func TestW3CCredential_ValidateBJJSignatureProofIssuerStatus(t *testing.T) {
	in := `{
        "id": "urn:uuid:c784e54c-b14e-11ee-94df-a27b3ddbdc28",
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://schema.iden3.io/core/jsonld/iden3proofs.jsonld",
            "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld"
        ],
        "type": [
            "VerifiableCredential",
            "KYCAgeCredential"
        ],
        "expirationDate": "2361-03-21T21:14:48+02:00",
        "issuanceDate": "2024-01-12T15:30:40.800436+02:00",
        "credentialSubject": {
            "birthday": 19960424,
            "documentType": 2,
            "id": "did:polygonid:polygon:mumbai:2qDwkysfn58urGGatGYsHKqzYPsy5p3mc9yxZZTeqh",
            "type": "KYCAgeCredential"
        },
        "credentialStatus": {
            "id": "http://localhost:8001/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qNuE5Jxmvrx6EithQ5bMs4DcWN91SjxepUzdQtddn/claims/revocation/status/1737529009",
            "revocationNonce": 1737529009,
            "type": "SparseMerkleTreeProof"
        },
        "issuer": "did:polygonid:polygon:mumbai:2qNuE5Jxmvrx6EithQ5bMs4DcWN91SjxepUzdQtddn",
        "credentialSchema": {
            "id": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/KYCAgeCredential-v3.json",
            "type": "JsonSchema2023"
        },
        "proof": [
            {
                "type": "BJJSignature2021",
                "issuerData": {
                    "id": "did:polygonid:polygon:mumbai:2qNuE5Jxmvrx6EithQ5bMs4DcWN91SjxepUzdQtddn",
                    "state": {
                        "claimsTreeRoot": "9af7b27d7176f465dc9acfd7dc937bae5df1d1cd34d682692f1ea6bf7cedf514",
                        "value": "95e4f8437be5d50a569bb532713110e4f5d2ac97765fae54041dddae9638a119"
                    },
                    "authCoreClaim": "cca3371a6cb1b715004407e325bd993c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000d95ae65475a9b380ca6118927f741c06466e951c25bb7b03a1505d597fc078222fe8db4747e2bf9c847308b283a5c17eeba4e50ced3283d24cce665b35f701050000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                    "mtp": {
                        "existence": true,
                        "siblings": []
                    },
                    "credentialStatus": {
                        "id": "http://localhost:8001/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qNuE5Jxmvrx6EithQ5bMs4DcWN91SjxepUzdQtddn/claims/revocation/status/0",
                        "revocationNonce": 0,
                        "type": "SparseMerkleTreeProof"
                    }
                },
                "coreClaim": "c9b2370371b7fa8b3dab2a5ba81b68382a0000000000000000000000000000000212208b10849a2f9bbacd2a583d4177ec460ac4f599d8355cfc39d820d90c00c7f1c984807cf958a96b0850ee8e9f495902a87c3a8f11a2fbcabe10fdea702c0000000000000000000000000000000000000000000000000000000000000000b196906700000000281cdcdf0200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "signature": "16a3e5cf7638bf843dbff803aeafa9c8735dde795cc9b8638c6b1963f290f890cad183481dee4f6376ed3496296f30170d1558f929486ec8ada00aa1d1104005"
            }
        ]
    }`
	var vc W3CCredential
	err := json.Unmarshal([]byte(in), &vc)
	require.NoError(t, err)

	resolverURL := "http://my-universal-resolver/1.0/identifiers"

	defer tst.MockHTTPClient(t,
		map[string]string{
			"http://my-universal-resolver/1.0/identifiers/did%3Apolygonid%3Apolygon%3Amumbai%3A2qNuE5Jxmvrx6EithQ5bMs4DcWN91SjxepUzdQtddn?state=95e4f8437be5d50a569bb532713110e4f5d2ac97765fae54041dddae9638a119": `./testdata/verifycred//my-universal-resolver-5.json`,
			"http://localhost:8001/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qNuE5Jxmvrx6EithQ5bMs4DcWN91SjxepUzdQtddn/claims/revocation/status/0":                                                  `./testdata/verifycred//issuer-state-response.json`,
		})()

	resolverRegisty := CredentialStatusResolverRegistry{}
	resolverRegisty.Register(SparseMerkleTreeProof, IssuerResolver{})
	verifyConfig := []W3CProofVerificationOpt{WithStatusResolverRegistry(&resolverRegisty)}
	err = vc.VerifyProof(context.Background(), BJJSignatureProofType,
		HTTPDIDResolver{resolverURL: resolverURL}, verifyConfig...)
	require.NoError(t, err)
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
