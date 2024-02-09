package verifiable

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/iden3/go-schema-processor/v2/merklize"
	tst "github.com/iden3/go-schema-processor/v2/testing"
	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/require"
)

func TestParser_parseSlots(t *testing.T) {
	defer tst.MockHTTPClient(t,
		map[string]string{
			"https://www.w3.org/2018/credentials/v1":              "../merklize/testdata/httpresp/credentials-v1.jsonld",
			"https://example.com/schema-delivery-address.json-ld": "../json/testdata/schema-delivery-address.json-ld",
		},
		tst.IgnoreUntouchedURLs())()

	credentialBytes, err := os.ReadFile("../json/testdata/non-merklized-1.json-ld")
	require.NoError(t, err)

	var credential W3CCredential
	err = json.Unmarshal(credentialBytes, &credential)
	require.NoError(t, err)

	nullSlot := make([]byte, 32)
	ctx := context.Background()

	mz, err := credential.Merklize(ctx)
	require.NoError(t, err)

	credentialType, err := findCredentialType(mz)
	require.NoError(t, err)

	slots, nonMerklized, err := parseSlots(mz, credential, credentialType)
	require.True(t, nonMerklized)
	require.NoError(t, err)
	require.NotEqual(t, nullSlot, slots.IndexA)
	require.Equal(t, nullSlot, slots.IndexB)
	require.Equal(t, nullSlot, slots.ValueA)
	require.NotEqual(t, nullSlot, slots.ValueB)
}

func TestGetSerializationAttr(t *testing.T) {
	defer tst.MockHTTPClient(t,
		map[string]string{
			"https://www.w3.org/2018/credentials/v1":              "../merklize/testdata/httpresp/credentials-v1.jsonld",
			"https://example.com/schema-delivery-address.json-ld": "../json/testdata/schema-delivery-address.json-ld",
		},
		tst.IgnoreUntouchedURLs())()

	vc := W3CCredential{
		Context: []string{
			"https://www.w3.org/2018/credentials/v1",
			"https://example.com/schema-delivery-address.json-ld",
		},
	}

	options := ld.NewJsonLdOptions("")

	t.Run("by type name", func(t *testing.T) {
		serAttr, err := getSerializationAttr(vc, options,
			"DeliverAddressMultiTestForked")
		require.NoError(t, err)
		require.Equal(t,
			"iden3:v1:slotIndexA=price&slotValueB=postalProviderInformation.insured",
			serAttr)
	})

	t.Run("by type id", func(t *testing.T) {
		serAttr, err := getSerializationAttr(vc, options,
			"urn:uuid:ac2ede19-b3b9-454d-b1a9-a7b3d5763100")
		require.NoError(t, err)
		require.Equal(t,
			"iden3:v1:slotIndexA=price&slotValueB=postalProviderInformation.insured",
			serAttr)
	})

	t.Run("unknown type", func(t *testing.T) {
		serAttr, err := getSerializationAttr(vc, options, "bla-bla")
		require.NoError(t, err)
		require.Equal(t, "", serAttr)
	})
}

func TestFindCredentialType(t *testing.T) {
	mockHTTP := func(t testing.TB) func() {
		return tst.MockHTTPClient(t,
			map[string]string{
				"https://www.w3.org/2018/credentials/v1":              "../merklize/testdata/httpresp/credentials-v1.jsonld",
				"https://example.com/schema-delivery-address.json-ld": "../json/testdata/schema-delivery-address.json-ld",
			},
			// requests are cached, so we don't check them on second and
			// further runs
			tst.IgnoreUntouchedURLs(),
		)
	}

	ctx := context.Background()

	t.Run("type from internal field", func(t *testing.T) {
		defer mockHTTP(t)()
		rdr := strings.NewReader(`
{
    "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://example.com/schema-delivery-address.json-ld"
    ],
    "@type": [
        "VerifiableCredential",
        "DeliverAddressMultiTestForked"
    ],
    "credentialSubject": {
        "isPostalProvider": false,
        "postalProviderInformation": {
            "insured": true,
            "weight": "1.3"
        },
        "price": "123.52",
        "type": "DeliverAddressMultiTestForked"
    }
}`)
		mz, err := merklize.MerklizeJSONLD(ctx, rdr)
		require.NoError(t, err)
		typeID, err := findCredentialType(mz)
		require.NoError(t, err)
		require.Equal(t, "urn:uuid:ac2ede19-b3b9-454d-b1a9-a7b3d5763100", typeID)
	})

	t.Run("type from top level", func(t *testing.T) {
		defer mockHTTP(t)()
		rdr := strings.NewReader(`
{
    "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://example.com/schema-delivery-address.json-ld"
    ],
    "@type": [
        "VerifiableCredential",
        "DeliverAddressMultiTestForked"
    ],
    "credentialSubject": {
        "isPostalProvider": false,
        "postalProviderInformation": {
            "insured": true,
            "weight": "1.3"
        },
        "price": "123.52"
    }
}`)
		mz, err := merklize.MerklizeJSONLD(ctx, rdr)
		require.NoError(t, err)
		typeID, err := findCredentialType(mz)
		require.NoError(t, err)
		require.Equal(t, "urn:uuid:ac2ede19-b3b9-454d-b1a9-a7b3d5763100", typeID)
	})

	t.Run("type from top level when internal incorrect", func(t *testing.T) {
		defer mockHTTP(t)()
		rdr := strings.NewReader(`
{
    "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://example.com/schema-delivery-address.json-ld"
    ],
    "@type": [
        "VerifiableCredential",
        "DeliverAddressMultiTestForked"
    ],
    "credentialSubject": {
        "isPostalProvider": false,
        "postalProviderInformation": {
            "insured": true,
            "weight": "1.3"
        },
        "price": "123.52",
        "type": ["EcdsaSecp256k1Signature2019", "EcdsaSecp256r1Signature2019"]
    }
}`)
		mz, err := merklize.MerklizeJSONLD(ctx, rdr)
		require.NoError(t, err)
		typeID, err := findCredentialType(mz)
		require.NoError(t, err)
		require.Equal(t, "urn:uuid:ac2ede19-b3b9-454d-b1a9-a7b3d5763100", typeID)
	})

	t.Run("unexpected top level 1", func(t *testing.T) {
		defer mockHTTP(t)()
		rdr := strings.NewReader(`
{
    "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://example.com/schema-delivery-address.json-ld"
    ],
    "@type": [
        "VerifiableCredential",
        "DeliverAddressMultiTestForked",
		"EcdsaSecp256k1Signature2019"
    ]
}`)
		mz, err := merklize.MerklizeJSONLD(ctx, rdr)
		require.NoError(t, err)
		_, err = findCredentialType(mz)
		require.EqualError(t, err, "top level @type expected to be of length 2")
	})

	t.Run("unexpected top level 2", func(t *testing.T) {
		defer mockHTTP(t)()
		rdr := strings.NewReader(`
{
    "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://example.com/schema-delivery-address.json-ld"
    ],
    "@type": ["DeliverAddressMultiTestForked", "EcdsaSecp256k1Signature2019"]
}`)
		mz, err := merklize.MerklizeJSONLD(ctx, rdr)
		require.NoError(t, err)
		_, err = findCredentialType(mz)
		require.EqualError(t, err,
			"@type(s) are expected to contain VerifiableCredential type")
	})

}
