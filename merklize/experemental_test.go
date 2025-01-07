package merklize

import (
	"context"
	"fmt"
	"math/big"
	"regexp"
	"testing"

	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-merkletree-sql/v2/db/memory"
	"github.com/stretchr/testify/require"
)

var conskeys = []string{
	"credentialSubject.type",
	"credentialStatus.type",
	"type.id",
	"credentialSchema.type",
	"credentialSchema.id",
}

func isConsKey(key string) bool {
	for _, k := range conskeys {
		if k == key {
			return true
		}
	}
	return false
}

const credentialAnonAadhaar = `
{
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://schema.iden3.io/core/jsonld/iden3proofs.jsonld",
      "https://gist.githubusercontent.com/ilya-korotya/078de56c274d44ea5a9579e137bd4301/raw/bfc67afc2246cf40a3fc508f0de9f689f318373d/AnonAadhaar.jsonld"
    ],
    "type": [
      "VerifiableCredential",
      "AnonAadhaar"
    ],
    "issuanceDate": "2024-12-23T20:53:09.512228532Z",
    "credentialSubject": {
      "birthday": 19840101,
      "gender": 77,
      "id": "did:iden3:privado:main:2Scn2RfosbkQDMQzQM5nCz3Nk5GnbzZCWzGCd3tc2G",
      "pinCode": 110051,
      "state": 452723500356,
      "type": "AnonAadhaar"
    },
    "credentialStatus": {
      "id": "https://issuer-node-core-api-demo.privado.id/v2/agent",
      "revocationNonce": 954548273,
      "type": "Iden3commRevocationStatusV1.0"
    },
    "issuer": "did:iden3:privado:main:2Si3eZUE6XetYsmU5dyUK2Cvaxr1EEe65vdv2BML4L",
    "credentialSchema": {
      "id": "https://gist.githubusercontent.com/ilya-korotya/601c46ca5a7487ae6e1946b4aab22b1d/raw/3aa88a8dd666253869fb0d86ae58d0ce3d040203/AnonAadhaar.json",
      "type": "JsonSchema2023"
    }
}
`

type leaf struct {
	key     *big.Int
	value   *big.Int
	comment string
}

func (l *leaf) String() string {
	return fmt.Sprintf("key: %s, value: %s // %s", l.key, l.value, l.comment)
}

func TestAnonAadhaar(t *testing.T) {
	dataset := getDataset(t, credentialAnonAadhaar)
	entries, err := EntriesFromRDF(dataset)
	require.NoError(t, err)

	var hardcoded []*leaf
	var tochange []*leaf
	for _, entry := range entries {
		k, err := entry.KeyMtEntry()
		require.NoError(t, err)
		v, err := entry.ValueMtEntry()
		require.NoError(t, err)
		key := keyExtractor(entry.key.parts)
		if isConsKey(key) {
			hardcoded = append(hardcoded, &leaf{k, v, key})
		} else {
			tochange = append(tochange, &leaf{k, big.NewInt(0), key})
		}
	}

	printKeys(hardcoded, tochange)

	root, err := calculateTemplateRoot(hardcoded, tochange)
	require.NoError(t, err)
	fmt.Println("Template root:", root)
}

func printKeys(h, tch []*leaf) {
	fmt.Println("Hardcoded:")
	for _, k := range h {
		fmt.Println(k)
	}
	fmt.Println("\nTo change:")
	for _, k := range tch {
		fmt.Println(k)
	}
}

func keyExtractor(p []interface{}) string {
	input := fmt.Sprintf("%s", p)
	regex := regexp.MustCompile(`(?:https?://[\w./#-]+#(\w+))(?:(?:\s+|%!\w+\(int=(\d+)\))\s*(?:urn:uuid:[\w-]+#|https?://[\w./-]+#)?(\w*))?`)

	matches := regex.FindAllStringSubmatch(input, -1)

	var res string
	for _, match := range matches {
		key := match[1]
		if match[3] != "" {
			if match[2] != "" {
				res = fmt.Sprintf("%s[%s]", match[3], match[2])
			} else {
				res = fmt.Sprintf("%s.%s", key, match[3])
			}
		} else {
			res = fmt.Sprintf("%s.id", key)
		}
	}

	return res
}

func calculateTemplateRoot(hardcoded, tochange []*leaf) (string, error) {
	treeStorage := memory.NewMemoryStorage()
	mt, err := merkletree.NewMerkleTree(context.Background(), treeStorage, 10)
	if err != nil {
		return "", fmt.Errorf("failed to create merkle tree: %w", err)
	}
	all := append(hardcoded, tochange...)

	for _, node := range all {
		err := mt.Add(context.Background(), node.key, node.value)
		if err != nil {
			return "", fmt.Errorf("failed to add node to merkle tree: %w", err)
		}
	}
	return mt.Root().BigInt().String(), nil
}
