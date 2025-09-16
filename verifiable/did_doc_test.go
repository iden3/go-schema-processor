package verifiable

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGistInfoProof_JSON_Unmarshal_Marshal(t *testing.T) {
	in := `{
			"type": "Iden3SparseMerkleTreeProof",
            "existence": true,
            "siblings": [
              "1362535354014507859867367590099676368653533743679052873579632656491435384778",
              "11921658728427020988213827821301476324611070652461851254718454837799781090130",
              "14437346982570868636439880944965253984519016799788166801110955632411304936181",
              "7008861419840281183040259263097349725975544589604657255528412015559570756430",
              "12919820512704336619019284308940813320869421725637735792759784734583345278320",
              "10847811404722023193836917968795578158377516355689063480344319030883153551997",
              "7501704662566146993443082955484915477984763397289571730014912300112522436190",
              "15319676397008451935308301168627943776087314271828889852225733045012068685123",
              "13580625240484189131905658989056965789342053909035527622054608432235108291371",
              "15701076866894648427718398501239266270187920232235356979681337424723013748037",
              "18391822292664048359198417757393480551710071249895941413402198372170950884043",
              "0",
              "1956510840262628579400226733676154238486255274390348671620337333964042370619",
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
		}`

	var proof GistInfoProof
	err := json.Unmarshal([]byte(in), &proof)
	require.NoError(t, err)
	require.Equal(t, Iden3SparseMerkleTreeProofType, proof.Type)
	require.Equal(t, true, proof.Existence)
	require.Len(t, proof.Proof.AllSiblings(), 64)
	require.Nil(t, proof.Proof.NodeAux)

	marshaled, err := proof.MarshalJSON()
	require.NoError(t, err)
	require.JSONEq(t, in, string(marshaled))
}

func TestAuthenticationMarshalUnmarshal(t *testing.T) {
	in := "\"did:pkh:eip155:80002:0xE9D7fCDf32dF4772A7EF7C24c76aB40E4A42274a\""

	var authentication Authentication
	err := authentication.UnmarshalJSON([]byte(in))
	require.NoError(t, err)

	marshaled, err := authentication.MarshalJSON()
	require.NoError(t, err)
	require.JSONEq(t, in, string(marshaled))
}

func TestDidDoc_ResolveAssertionVerificationMethods(t *testing.T) {
	vm1 := CommonVerificationMethod{ID: "did:example:123#key-1", Type: "EcdsaSecp256k1VerificationKey2019", Controller: "did:example:123"}
	vm2 := CommonVerificationMethod{ID: "did:example:123#key-2", Type: "EcdsaSecp256k1VerificationKey2019", Controller: "did:example:123"}

	tests := []struct {
		name    string
		doc     DIDDocument
		wantIDs []string
	}{
		{
			name: "Resolve did reference and inline methods",
			doc: DIDDocument{
				VerificationMethod: []CommonVerificationMethod{vm1, vm2},
				// authentication contains a DID reference to vm1 and inline vm2
				Authentication: []Authentication{
					{CommonVerificationMethod: CommonVerificationMethod{}, did: vm1.ID},
					{CommonVerificationMethod: vm2},
				},
			},
			wantIDs: []string{vm1.ID, vm2.ID},
		},
		{
			name: "Resolve one authentication did reference",
			doc: DIDDocument{
				VerificationMethod: []CommonVerificationMethod{vm1, vm2},
				// authentication contains a DID reference to vm1 and inline vm2
				Authentication: []Authentication{
					{CommonVerificationMethod: CommonVerificationMethod{}, did: vm1.ID},
				},
			},
			wantIDs: []string{vm1.ID},
		},
		{
			name: "Resolve one authentication method without verification methods",
			doc: DIDDocument{
				VerificationMethod: []CommonVerificationMethod{},
				Authentication: []Authentication{
					{CommonVerificationMethod: vm1},
				},
			},
			wantIDs: []string{vm1.ID},
		},
		{
			name: "Resolve empty authentication",
			doc: DIDDocument{
				VerificationMethod: []CommonVerificationMethod{vm1, vm2},
				Authentication:     []Authentication{},
			},
			wantIDs: []string{},
		},
		{
			name: "Resolve empty authentication and verification methods",
			doc: DIDDocument{
				VerificationMethod: []CommonVerificationMethod{},
				Authentication:     []Authentication{},
			},
			wantIDs: []string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.doc.ResolveAssertionVerificationMethods()
			require.NoError(t, err)
			require.Len(t, got, len(tc.wantIDs))
			for i, vm := range got {
				require.Equal(t, tc.wantIDs[i], vm.ID)
			}
		})
	}
}

func TestDidDoc_ResolveKeyAgreementVerificationMethods(t *testing.T) {
	vm1 := CommonVerificationMethod{ID: "did:example:123#key-1", Type: "EcdsaSecp256k1VerificationKey2019", Controller: "did:example:123"}
	vm2 := CommonVerificationMethod{ID: "did:example:123#key-2", Type: "EcdsaSecp256k1VerificationKey2019", Controller: "did:example:123"}

	tests := []struct {
		name    string
		doc     DIDDocument
		wantIDs []string
	}{
		{
			name: "Resolve did reference and inline methods",
			doc: DIDDocument{
				VerificationMethod: []CommonVerificationMethod{vm1, vm2},
				KeyAgreement: []Authentication{
					{CommonVerificationMethod: CommonVerificationMethod{}, did: vm1.ID},
					{CommonVerificationMethod: vm2},
				},
			},
			wantIDs: []string{vm1.ID, vm2.ID},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.doc.ResolveKeyAgreementVerificationMethods()
			require.NoError(t, err)
			require.Len(t, got, len(tc.wantIDs))
		})
	}
}

func TestDidDoc_ResolveAssertionVerificationMethods_Errors(t *testing.T) {
	vm1 := CommonVerificationMethod{ID: "did:example:123#key-1", Type: "EcdsaSecp256k1VerificationKey2019", Controller: "did:example:123"}

	tests := []struct {
		name       string
		doc        DIDDocument
		errContain string
	}{
		{
			name: "missing referenced vm returns error",
			doc: DIDDocument{
				VerificationMethod: []CommonVerificationMethod{vm1},
				Authentication: []Authentication{
					{CommonVerificationMethod: CommonVerificationMethod{}, did: "did:example:123#missing"},
				},
			},
			errContain: "found 0 verification methods",
		},
		{
			name: "missing referenced vm plus embedded one returns error",
			doc: DIDDocument{
				VerificationMethod: []CommonVerificationMethod{vm1},
				Authentication: []Authentication{
					{CommonVerificationMethod: CommonVerificationMethod{}, did: "did:example:123#missing"},
					{CommonVerificationMethod: vm1},
				},
			},
			errContain: "found 0 verification methods",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.doc.ResolveAssertionVerificationMethods()
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.errContain)
		})
	}
}

func TestCommonVerificationMethods_FilterBy(t *testing.T) {
	vm1 := CommonVerificationMethod{
		ID:         "did:example:123#key-1",
		Type:       "EcdsaSecp256k1VerificationKey2019",
		Controller: "did:example:123",
		PublicKeyJwk: map[string]interface{}{
			"kty": "EC",
			"crv": "secp256k1",
			"alg": "ES256K",
		},
	}
	vm2 := CommonVerificationMethod{
		ID:         "did:example:123#key-2",
		Type:       "Ed25519VerificationKey2018",
		Controller: "did:example:123",
		PublicKeyJwk: map[string]interface{}{
			"kty": "OKP",
			"crv": "Ed25519",
			"alg": "EdDSA",
		},
	}
	vm3 := CommonVerificationMethod{
		ID:         "did:example:123#key-3",
		Type:       "X25519KeyAgreementKey2019",
		Controller: "did:example:123",
		PublicKeyJwk: map[string]interface{}{
			"kty": "OKP",
			"crv": "X25519",
			"alg": "ECDH-ES",
		},
	}

	tests := []struct {
		name    string
		vms     CommonVerificationMethods
		opts    []VerificationMethodFilterOpt
		wantIDs []string
	}{
		{
			name:    "filter by ID",
			vms:     CommonVerificationMethods{vm1, vm2, vm3},
			opts:    []VerificationMethodFilterOpt{WithID(vm2.ID)},
			wantIDs: []string{vm2.ID},
		},
		{
			name: "filter by Type",
			vms: CommonVerificationMethods{
				vm1, vm2, vm3,
				CommonVerificationMethod{
					ID:   "did:example:123#key-extra",
					Type: vm2.Type,
				}},
			opts:    []VerificationMethodFilterOpt{WithType(vm2.Type)},
			wantIDs: []string{vm2.ID, "did:example:123#key-extra"},
		},
		{
			name:    "find by Key Type",
			vms:     CommonVerificationMethods{vm1, vm2, vm3},
			opts:    []VerificationMethodFilterOpt{WithJWKType("OKP")},
			wantIDs: []string{vm2.ID, vm3.ID},
		},
		{
			name:    "find by Key Algorithm",
			vms:     CommonVerificationMethods{vm1, vm2, vm3},
			opts:    []VerificationMethodFilterOpt{WithJWKAlgorithm("EdDSA")},
			wantIDs: []string{vm2.ID},
		},
		{
			name: "find by Type and Key Type",
			vms: CommonVerificationMethods{vm1, vm2, vm3, {
				ID:   "did:example:123#key-extra",
				Type: "Ed25519VerificationKey2018",
				PublicKeyJwk: map[string]interface{}{
					"kty": "BJJ",
				},
			}},
			opts: []VerificationMethodFilterOpt{
				WithType("Ed25519VerificationKey2018"),
				WithJWKType("OKP"),
			},
			wantIDs: []string{vm2.ID},
		},
		{
			name: "filter by empty JWK. No panic",
			vms: CommonVerificationMethods{
				CommonVerificationMethod{
					ID:           "did:example:123#key-1",
					Type:         "EcdsaSecp256k1VerificationKey2019",
					Controller:   "did:example:123",
					PublicKeyHex: "asd",
				},
			},
			opts:    []VerificationMethodFilterOpt{WithJWKType("OKP"), WithJWKAlgorithm("EdDSA")},
			wantIDs: []string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.vms.FilterBy(tc.opts...)
			require.NoError(t, err)
			require.Len(t, got, len(tc.wantIDs))
			for i, vm := range got {
				require.Equal(t, tc.wantIDs[i], vm.ID)
			}
		})
	}
}

func TestCommonVerificationMethods_AllVerificationMethods(t *testing.T) {
	tests := []struct {
		name    string
		doc     DIDDocument
		wantIDs []string
	}{
		{
			name: "All VMs from all sections",
			doc: DIDDocument{
				VerificationMethod: []CommonVerificationMethod{
					{ID: "did:example:123#key-1"},
					{ID: "did:example:123#key-2"},
				},
				Authentication: []Authentication{
					{CommonVerificationMethod: CommonVerificationMethod{
						ID: "did:example:123#key-3"}},
				},
				AssertionMethod: []Authentication{
					{CommonVerificationMethod: CommonVerificationMethod{
						ID: "did:example:123#key-4"}},
				},
				KeyAgreement: []Authentication{
					{CommonVerificationMethod: CommonVerificationMethod{
						ID: "did:example:123#key-5"}},
				},
			},
			wantIDs: []string{
				"did:example:123#key-1",
				"did:example:123#key-2",
				"did:example:123#key-3",
				"did:example:123#key-4",
				"did:example:123#key-5",
			},
		},
		{
			name: "Duplicate VMs are returned only once",
			doc: DIDDocument{
				VerificationMethod: []CommonVerificationMethod{
					{ID: "did:example:123#key-1"},
					{ID: "did:example:123#key-2"},
				},
				Authentication: []Authentication{
					{CommonVerificationMethod: CommonVerificationMethod{ID: "did:example:123#key-2"}},
				},
				AssertionMethod: []Authentication{
					{CommonVerificationMethod: CommonVerificationMethod{ID: "did:example:123#key-4"}},
				},
			},
			wantIDs: []string{
				"did:example:123#key-1",
				"did:example:123#key-2",
				"did:example:123#key-4",
			},
		},
		{
			name: "Duplicate VMs with reference to VerificationMethod",
			doc: DIDDocument{
				VerificationMethod: []CommonVerificationMethod{
					{ID: "did:example:123#key-1"},
					{ID: "did:example:123#key-2"},
				},
				Authentication: []Authentication{
					{CommonVerificationMethod: CommonVerificationMethod{ID: "did:example:123#key-2"}},
				},
				AssertionMethod: []Authentication{
					{
						CommonVerificationMethod: CommonVerificationMethod{},
						did:                      "did:example:123#key-2",
					},
				},
			},
			wantIDs: []string{
				"did:example:123#key-1",
				"did:example:123#key-2",
			},
		},
		{
			name: "Don't return an error if did reference isn't found in VerificationMethod",
			doc: DIDDocument{
				VerificationMethod: []CommonVerificationMethod{
					{ID: "did:example:123#key-1"},
					{ID: "did:example:123#key-2"},
				},
				AssertionMethod: []Authentication{
					{
						CommonVerificationMethod: CommonVerificationMethod{},
						did:                      "did:example:123#key-not-found",
					},
				},
			},
			wantIDs: []string{
				"did:example:123#key-1",
				"did:example:123#key-2",
			},
		},
		{
			name: "All is empty. Return empty",
			doc: DIDDocument{
				VerificationMethod: []CommonVerificationMethod{},
				AssertionMethod:    []Authentication{},
				Authentication:     []Authentication{},
				KeyAgreement:       []Authentication{},
			},
			wantIDs: []string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.doc.AllVerificationMethods()
			onlyIDs := make([]string, len(got))
			for i, vm := range got {
				onlyIDs[i] = vm.ID
			}
			require.ElementsMatch(t, tc.wantIDs, onlyIDs)
		})
	}
}
