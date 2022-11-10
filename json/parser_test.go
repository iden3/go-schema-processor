package json

import (
	"encoding/json"
	"os"
	"testing"

	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-schema-processor/verifiable"
	"github.com/stretchr/testify/require"
)

func TestParser_ParseSlots(t *testing.T) {

	credentialBytes, err := os.ReadFile("testdata/credential.json")
	require.NoError(t, err)

	var credential verifiable.Iden3Credential

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

	var credential verifiable.Iden3Credential

	err = json.Unmarshal(credentialBytes, &credential)
	require.NoError(t, err)

	schemaBytes, err := os.ReadFile("testdata/schema-slots.json")
	require.NoError(t, err)

	parser := Parser{}
	claim, err := parser.ParseClaim(credential, schemaBytes)
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
	require.Equal(t, credential.Updatable, claim.GetFlagUpdatable())
	exp, _ := claim.GetExpirationDate()
	require.Equal(t, credential.Expiration.Unix(), exp.Unix())

}
func TestParser_ParseClaimWithMerklizedRoot(t *testing.T) {

	credentialBytes, err := os.ReadFile("testdata/credential.json")
	require.NoError(t, err)

	var credential verifiable.Iden3Credential

	err = json.Unmarshal(credentialBytes, &credential)
	require.NoError(t, err)

	schemaBytes, err := os.ReadFile("testdata/schema-merklization.json")
	require.NoError(t, err)

	parser := Parser{}
	claim, err := parser.ParseClaim(credential, schemaBytes)
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
	core.ParseDIDFromID(idFromClaim)
	require.Equal(t, did, didFromClaim.String())
	require.Equal(t, credential.Updatable, claim.GetFlagUpdatable())
	exp, _ := claim.GetExpirationDate()
	require.Equal(t, credential.Expiration.Unix(), exp.Unix())

}
