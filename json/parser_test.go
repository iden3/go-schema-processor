package json

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-schema-processor/v2/merklize"
	tst "github.com/iden3/go-schema-processor/v2/testing"
	"github.com/iden3/go-schema-processor/v2/verifiable"
	"github.com/stretchr/testify/require"
)

func TestParser_ParseClaimWithDataSlots(t *testing.T) {
	defer tst.MockHTTPClient(t,
		map[string]string{
			"https://www.w3.org/2018/credentials/v1":              "../merklize/testdata/httpresp/credentials-v1.jsonld",
			"https://example.com/schema-delivery-address.json-ld": "testdata/schema-delivery-address.json-ld",
		},
		tst.IgnoreUntouchedURLs())()

	credentialBytes, err := os.ReadFile("testdata/non-merklized-1.json-ld")
	require.NoError(t, err)

	var credential verifiable.W3CCredential

	err = json.Unmarshal(credentialBytes, &credential)
	require.NoError(t, err)

	parser := Parser{}

	opts := verifiable.CoreClaimOptions{
		RevNonce:              127366661,
		Version:               0,
		SubjectPosition:       verifiable.CredentialSubjectPositionIndex,
		MerklizedRootPosition: verifiable.CredentialMerklizedRootPositionNone,
		Updatable:             true,
	}

	claim, err := parser.ParseClaim(context.Background(), credential, &opts)
	require.NoError(t, err)

	index, value := claim.RawSlots()

	require.NotEmpty(t, index[2])
	require.Empty(t, index[3])

	require.Empty(t, value[2])
	require.NotEmpty(t, value[3])

	_, err = claim.GetID()
	require.EqualError(t, err, "ID is not set")
	require.Equal(t, opts.Updatable, claim.GetFlagUpdatable())
	_, ok := claim.GetExpirationDate()
	require.False(t, ok)
}

func TestParser_ParseClaimWithMerklizedRoot(t *testing.T) {
	defer tst.MockHTTPClient(t,
		map[string]string{
			"https://www.w3.org/2018/credentials/v1": "../merklize/testdata/httpresp/credentials-v1.jsonld",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld": "../merklize/testdata/httpresp/iden3credential-v2.json-ld",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":             "../merklize/testdata/httpresp/kyc-v3.json-ld",
		},
		tst.IgnoreUntouchedURLs())()

	credentialBytes, err := os.ReadFile("testdata/credential-merklized.json")
	require.NoError(t, err)

	var credential verifiable.W3CCredential

	err = json.Unmarshal(credentialBytes, &credential)
	require.NoError(t, err)

	parser := Parser{}

	opts := verifiable.CoreClaimOptions{
		RevNonce:              127366661,
		Version:               0,
		SubjectPosition:       verifiable.CredentialSubjectPositionIndex,
		MerklizedRootPosition: verifiable.CredentialMerklizedRootPositionIndex,
		Updatable:             true,
	}
	claim, err := parser.ParseClaim(context.Background(), credential, &opts)
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
	contextBytes, err := os.ReadFile("testdata/schema-delivery-address.json-ld")
	require.NoError(t, err)

	parser := Parser{}

	slotIndex, err := parser.GetFieldSlotIndex("price",
		"DeliverAddressMultiTestForked", contextBytes)
	require.NoError(t, err)
	require.Equal(t, 2, slotIndex)

	slotIndex, err = parser.GetFieldSlotIndex(
		"postalProviderInformation.insured", "DeliverAddressMultiTestForked",
		contextBytes)
	require.NoError(t, err)
	require.Equal(t, 7, slotIndex)
}
