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
