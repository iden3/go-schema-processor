package json

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-schema-processor/merklize"
	"github.com/iden3/go-schema-processor/processor"
	"github.com/iden3/go-schema-processor/verifiable"
	"github.com/stretchr/testify/require"
)

func TestParser_ParseSlots(t *testing.T) {

	credentialBytes, err := os.ReadFile("testdata/credential.json")
	require.NoError(t, err)

	var credential verifiable.W3CCredential

	err = json.Unmarshal(credentialBytes, &credential)
	require.NoError(t, err)

	schemaBytes, err := os.ReadFile("testdata/schema-slots.json")
	require.NoError(t, err)

	parser := Parser{}
	slots, err := parser.ParseSlots(credential, schemaBytes)

	require.NoError(t, err)
	require.NotEmpty(t, slots.IndexA)
	require.NotEmpty(t, slots.IndexB)
	require.Empty(t, slots.ValueA)
	require.Empty(t, slots.ValueB)

}
func TestParser_ParseClaimWithDataSlots(t *testing.T) {

	credentialBytes, err := os.ReadFile("testdata/credential.json")
	require.NoError(t, err)

	var credential verifiable.W3CCredential

	err = json.Unmarshal(credentialBytes, &credential)
	require.NoError(t, err)

	schemaBytes, err := os.ReadFile("testdata/schema-slots.json")
	require.NoError(t, err)

	parser := Parser{}

	credentialType := "Test"

	opts := processor.CoreClaimOptions{
		RevNonce:              127366661,
		Version:               0,
		SubjectPosition:       "index",
		MerklizedRootPosition: "",
		Updatable:             true,
	}

	claim, err := parser.ParseClaim(context.Background(), credential, credentialType, schemaBytes, &opts)
	require.NoError(t, err)

	index, value := claim.RawSlots()

	require.NotEmpty(t, index[2])
	require.NotEmpty(t, index[3])

	require.Empty(t, value[2])
	require.Empty(t, value[3])

	did := credential.CredentialSubject["id"].(string)
	idFromClaim, err := claim.GetID()
	require.NoError(t, err)
	didFromClaim, err := core.ParseDIDFromID(idFromClaim)
	require.NoError(t, err)
	core.ParseDIDFromID(idFromClaim)
	require.Equal(t, did, didFromClaim.String())
	require.Equal(t, opts.Updatable, claim.GetFlagUpdatable())
	exp, _ := claim.GetExpirationDate()
	require.Equal(t, credential.Expiration.Unix(), exp.Unix())

}
func TestParser_ParseClaimWithMerklizedRoot(t *testing.T) {

	credentialBytes, err := os.ReadFile("testdata/credential.json")
	require.NoError(t, err)

	var credential verifiable.W3CCredential

	err = json.Unmarshal(credentialBytes, &credential)
	require.NoError(t, err)

	schemaBytes, err := os.ReadFile("testdata/schema-merklization.json")
	require.NoError(t, err)

	parser := Parser{}

	credentialType := "Test"

	opts := processor.CoreClaimOptions{
		RevNonce:              127366661,
		Version:               0,
		SubjectPosition:       "index",
		MerklizedRootPosition: "index",
		Updatable:             true,
	}
	claim, err := parser.ParseClaim(context.Background(), credential, credentialType, schemaBytes, &opts)
	require.NoError(t, err)

	index, value := claim.RawSlots()

	require.NotEmpty(t, index[2])
	require.Empty(t, index[3])

	require.Empty(t, value[2])
	require.Empty(t, value[3])

	did := credential.CredentialSubject["id"].(string)
	idFromClaim, err := claim.GetID()
	require.NoError(t, err)
	didFromClaim, err := core.ParseDIDFromID(idFromClaim)
	require.NoError(t, err)
	_, err = core.ParseDIDFromID(idFromClaim)
	require.NoError(t, err)
	require.Equal(t, did, didFromClaim.String())
	require.Equal(t, opts.Updatable, claim.GetFlagUpdatable())
	exp, _ := claim.GetExpirationDate()
	require.Equal(t, credential.Expiration.Unix(), exp.Unix())

	// proof of field

	// get root
	root := index[2]
	root.ToInt()

	path, err := merklize.NewPath(
		"https://www.w3.org/2018/credentials#credentialSubject",
		"https://github.com/iden3/claim-schema-vocab/blob/main/credentials/kyc.md#birthday")
	require.NoError(t, err)

	mk, err := credential.Merklize(context.Background())
	require.NoError(t, err)

	jsonP, v, err := mk.Proof(context.Background(), path)
	require.NotNil(t, v)
	require.Nil(t, err)
	me, err := v.MtEntry()
	require.NoError(t, err)
	require.Equal(t, true, jsonP.Existence)
	require.Equal(t, int64(credential.CredentialSubject["birthday"].(float64)),
		me.Int64())

}

func Test_GetFieldSlotIndex(t *testing.T) {
	schemaBytes, err := os.ReadFile("testdata/schema-slots.json")
	require.NoError(t, err)

	parser := Parser{}
	slotIndex, err := parser.GetFieldSlotIndex("birthday", schemaBytes)
	require.NoError(t, err)

	require.Equal(t, 2, slotIndex)
}
