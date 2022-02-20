package loaders

import (
	"bytes"
	"encoding/json"
	"fmt"
	shell "github.com/ipfs/go-ipfs-api"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

var str = `{"id":"c0f6ac87-603e-44cd-8d83-0caeb458d50d","@context":["https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential.json-ld","https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/auth.json-ld"],"@type":["Iden3Credential"],"expiration":"2361-03-21T21:14:48+02:00","updatable":false,"version":0,"rev_nonce":2034832188220019200,"credentialSubject":{"type":"AuthBJJCredential","x":"12747559771369266961976321746772881814229091957322087014312756428846389160887","y":"7732074634595480184356588475330446395691728690271550550016720788712795268212"},"credentialStatus":{"id":"http://localhost:8001/api/v1/identities/118VhAf6ng6J44FhNrGeYzSbJgGVmcpeXYFR2YTrZ6/claims/revocation/status/2034832188220019081","type":"SparseMerkleTreeProof"},"credentialSchema":{"@id":"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/auth.json-ld","type":"JsonSchemaValidator2018"},"proof":[{"@type":"BJJSignature2021","issuer":"118VhAf6ng6J44FhNrGeYzSbJgGVmcpeXYFR2YTrZ6","h_index":"c89cf5b95157f091f2d8bf49bc1a57cd7988da83bbcd982a74c5e8c70e566403","h_value":"0262b2cd6b9ae44cd9a39045c9bb03ad4e1f056cb81d855f1fc4ef0cdf827912","created":1642518655,"issuer_mtp":{"@type":"Iden3SparseMerkleProof","issuer":"118VhAf6ng6J44FhNrGeYzSbJgGVmcpeXYFR2YTrZ6","h_index":"201a02eb979be695702ea37d930309d2965d803541be5f7b3900459b2fad8726","h_value":"0654da1d53ca201cb42b767a6f12265ff7a08720b88a82182e0f20702479d12d","state":{"claims_tree_root":"a5087cfa6f2c7c565d831327091533f09999133df1df51104d2ce6f8e4d90529","value":"dca344e95da517a301729d94b213298b9de96dfddaf7aad9423d918ea3208820"},"mtp":{"existence":true,"siblings":[]}},"verification_method":"2764e2d8241b18c217010ebf90bebb30240d32c33f3007f33e42d58680813123","proof_value":"c354eb1006534c59766ed8398d49a9a614312e430c5373ea493395db6369d49485e9a0d63f3bfe9fd157294ffbf706b6b7df7a8662a58fae0056a046af1caa04","proof_purpose":"Authentication"},{"@type":"Iden3SparseMerkleProof","issuer":"118VhAf6ng6J44FhNrGeYzSbJgGVmcpeXYFR2YTrZ6","h_index":"c89cf5b95157f091f2d8bf49bc1a57cd7988da83bbcd982a74c5e8c70e566403","h_value":"0262b2cd6b9ae44cd9a39045c9bb03ad4e1f056cb81d855f1fc4ef0cdf827912","state":{"tx_id":"0xf2e23524ab76cb4f371b921a214ff411d5d391962899a2afe20f356e3bdc0c71","block_timestamp":1642522496,"block_number":11837707,"claims_tree_root":"bebcaee8444e93b6e32855f54e9f617d5fd654570badce7d6bc649304169681d","revocation_tree_root":"0000000000000000000000000000000000000000000000000000000000000000","value":"2806aa9a045b2a5503b12f2979b2d19933e803fd3dd73d8ad40dc138bc9a582e"},"mtp":{"existence":true,"siblings":["0","0","0","18555164879275043542501047154170418730098376961920428892719505858997411121317"]}}]}`

func UploadToIpfs() (string, error) {

	var m map[string]interface{}
	sh := shell.NewShell(os.Getenv("IPFS_URL"))
	err := json.Unmarshal([]byte(str), &m)
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}

	cid, err := sh.Add(bytes.NewReader(b))
	if err != nil {
		return "", err
	}

	return cid, nil

}

func TestUpload(t *testing.T) {

	a, err := UploadToIpfs()
	fmt.Println(a)
	assert.Nil(t, err)

}
