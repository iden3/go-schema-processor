package onchain

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	"github.com/iden3/go-schema-processor/v2/merklize"
	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/require"
)

func TestOnchainVerifiableCredential(t *testing.T) {
	const onchainVC = `
	{
		"id": "3",
		"context": [
			"https://www.w3.org/2018/credentials/v1",
			"https://schema.iden3.io/core/jsonld/iden3proofs.jsonld",
			"https://gist.githubusercontent.com/ilya-korotya/ac20f870943abd4805fe882ae8f3dccd/raw/1d9969a6d0454280c8d5e79b959faf9b3978b497/balance.jsonld"
		],
		"_type": [
			"VerifiableCredential",
			"Balance"
		],
		"expirationDate": "1706625594",
		"issuanceDate": "1704033594",
		"issuer": "19484705861374617667364863063732542917292760634421116245842578444633772546",
		"credentialSubject": [
			{
				"key": "id",
				"value": "26822544757879120710128032423896483348887667224594515131440237223704793602",
				"rawValue": "0x"
			},
			{
				"key": "balance",
				"value": "690135300",
				"rawValue": "0x"
			},
			{
				"key": "address",
				"value": "657065114158124047812701241180089030040156354062",
				"rawValue": "0x"
			},
			{
				"key": "type",
				"value": "0",
				"rawValue": "0x42616c616e6365"
			}
		],
		"credentialStatus": {
			"id": "/credentialStatus",
			"_type": "Iden3OnchainSparseMerkleTreeProof2023",
			"revocationNonce": "3"
		},
		"credentialSchema": {
			"id": "https://gist.githubusercontent.com/ilya-korotya/26ba81feb4da2f49f4b473661b80e8e3/raw/32113f4725088f32f31a6b06b4abdc94bc4b2d17/balance.json",
			"_type": "JsonSchema2023"
		},
		"proof": [
			{
				"_type": "Iden3SparseMerkleTreeProof",
				"coreClaim": [
					"3537648966163034177119037898189471968122",
					"26822544757879120710128032423896483348887667224594515131440237223704793602",
					"657065114158124047812701241180089030040156354062",
					"690135300",
					"31481685562160543310129659907",
					"0",
					"0",
					"0"
				],
				"issuerData": {
					"id": "19484705861374617667364863063732542917292760634421116245842578444633772546",
					"state": {
						"rootOfRoots": "9685113079065420245190835363036878393620765411639893110370159664015320514459",
						"claimsTreeRoot": "827856356923410814561808078394258006297045185715226162955032953413392332512",
						"revocationTreeRoot": "0",
						"value": "9945408944095719260820172624684690222316927707275276907391510066756172609919"
					}
				},
				"mtp": {
					"root": "827856356923410814561808078394258006297045185715226162955032953413392332512",
					"existence": true,
					"index": "6068115839546758919882142873457871778988822386370442144307890035616376926873",
					"value": "9611552909856359760707403504643353986342215687733480043581840705152258038362",
					"auxExistence": false,
					"auxIndex": "0",
					"auxValue": "0",
					"siblings": [
						"10047592599236199550778448513028226236019855222561771330384606295779768373542",
						"13805304332179448753405180527804403300885129271562960512563507472988960668727",
						"12183064868353685764219060406476387478463003700610432754986400106761414530729",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0"
					]
				}
			}
		]
	}
	`
	vc := new(Credential)
	err := json.Unmarshal([]byte(onchainVC), vc)
	require.NoError(t, err)

	w3ccred, err := ConvertVerifiableCredential(vc)
	require.NoError(t, err)
	bytesCred, err := json.Marshal(w3ccred)
	require.NoError(t, err)
	fmt.Println(string(bytesCred))
}

func TestConvertCredentialSubject(t *testing.T) {
	tests := []struct {
		name              string
		onchainCredential *Credential
		want              map[string]any
	}{
		{
			name: "Balance credential data",
			onchainCredential: &Credential{
				Context: []string{
					"https://www.w3.org/2018/credentials/v1",
					"https://schema.iden3.io/core/jsonld/iden3proofs.jsonld",
					"https://gist.githubusercontent.com/ilya-korotya/ac20f870943abd4805fe882ae8f3dccd/raw/1d9969a6d0454280c8d5e79b959faf9b3978b497/balance.jsonld",
				},
				Type: []string{
					"VerifiableCredential",
					"Balance",
				},
				CredentialSubject: []CredentialSubjectField{
					{"id", "26822544757879120710128032423896483348887667224594515131440237223704793602", ""},
					{"type", "", "0x42616c616e6365"},
					{"balance", "1699351689", ""},
					{"address", "657065114158124047812701241180089030040156354062", ""},
				},
			},
			want: map[string]any{
				"id":      "did:polygonid:polygon:mumbai:2qNgUX4CzfDdgppgfHn2ceT7wz8xUmDFR8zXzHFatE",
				"type":    "Balance",
				"balance": int64(1699351689),
				"address": "657065114158124047812701241180089030040156354062",
			},
		},
		{
			name: "Player credential data",
			onchainCredential: &Credential{
				Context: []string{
					"https://www.w3.org/2018/credentials/v1",
					"https://schema.iden3.io/core/jsonld/iden3proofs.jsonld",
					"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/player-nonmerklized.jsonld",
				},
				Type: []string{
					"VerifiableCredential",
					"Player",
				},
				CredentialSubject: []CredentialSubjectField{
					{"id", "26822544757879120710128032423896483348887667224594515131440237223704793602", ""},
					{"type", "", "0x506c61796572"},
					{
						// Since Solidity doesn't support fixed point numbers: https://docs.soliditylang.org/en/latest/types.html#fixed-point-numbers
						// Is possible to provide only test with integer value
						"power",
						// claim record
						func(t *testing.T) string {
							h, err := merklize.HashValue(ld.XSDDouble, 9)
							require.NoError(t, err)
							return h.String()
						}(t),
						// raw value
						func(_ *testing.T) string {
							// Solidity doesn't support fixed point numbers
							return "0x" + hex.EncodeToString(big.NewInt(9).Bytes())
						}(t),
					},
					{
						"nickname",
						// claim record
						func(t *testing.T) string {
							h, err := merklize.HashValue(ld.XSDString, "Alice")
							require.NoError(t, err)
							return h.String()
						}(t),
						// raw value
						func(_ *testing.T) string {
							return "0x" + hex.EncodeToString([]byte("Alice"))
						}(t),
					},
					{
						"createdAt",
						// claim record
						func(t *testing.T) string {
							h, err := merklize.HashValue(ld.XSDNS+"dateTime", "1997-04-16T07:04:42Z")
							require.NoError(t, err)
							return h.String()
						}(t),
						func(t *testing.T) string {
							return "0000000000000000000000000000000000000000000000000000000033547a0a"
						}(t),
					},
					{
						"active",
						// claim record
						func(t *testing.T) string {
							h, err := merklize.HashValue(ld.XSDBoolean, true)
							require.NoError(t, err)
							return h.String()
						}(t),
						"",
					},
				},
			},
			want: map[string]any{
				"id":        "did:polygonid:polygon:mumbai:2qNgUX4CzfDdgppgfHn2ceT7wz8xUmDFR8zXzHFatE",
				"type":      "Player",
				"power":     float64(9),
				"nickname":  "Alice",
				"createdAt": "1997-04-16T07:04:42Z",
				"active":    true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := (&Convertor{}).convertCredentialSubject(tt.onchainCredential)

			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
