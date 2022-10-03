package merklize

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/iden3/go-merkletree-sql"
	"github.com/iden3/go-merkletree-sql/db/memory"
	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/require"
)

const testDocument = `{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/citizenship/v1",
    "https://w3id.org/security/bbs/v1"
  ],
  "id": "https://issuer.oidp.uscis.gov/credentials/83627465",
  "type": ["VerifiableCredential", "PermanentResidentCard"],
  "issuer": "did:example:489398593",
  "identifier": 83627465,
  "name": "Permanent Resident Card",
  "description": "Government of Example Permanent Resident Card.",
  "issuanceDate": "2019-12-03T12:19:52Z",
  "expirationDate": "2029-12-03T12:19:52Z",
  "credentialSubject": [
    {
      "id": "did:example:b34ca6cd37bbf23",
      "type": ["PermanentResident", "Person"],
      "givenName": "JOHN",
      "familyName": "SMITH",
      "gender": "Male",
      "image": "data:image/png;base64,iVBORw0KGgokJggg==",
      "residentSince": "2015-01-01",
      "lprCategory": "C09",
      "lprNumber": "999-999-999",
      "commuterClassification": "C1",
      "birthCountry": "Bahamas",
      "birthDate": "1958-07-17"
    },
    {
      "id": "did:example:b34ca6cd37bbf24",
      "type": ["PermanentResident", "Person"],
      "givenName": "JOHN",
      "familyName": "SMITH",
      "gender": "Male",
      "image": "data:image/png;base64,iVBORw0KGgokJggg==",
      "residentSince": "2015-01-01",
      "lprCategory": "C09",
      "lprNumber": "999-999-999",
      "commuterClassification": "C1",
      "birthCountry": "Bahamas",
      "birthDate": "1958-07-18"
    }
  ]
}`

func getDataset(t testing.TB) *ld.RDFDataset {
	var obj map[string]interface{}
	err := json.Unmarshal([]byte(testDocument), &obj)
	if err != nil {
		panic(err)
	}

	proc := ld.NewJsonLdProcessor()
	options := ld.NewJsonLdOptions("")
	options.Algorithm = "URDNA2015"

	out4, err := proc.Normalize(obj, options)
	require.NoError(t, err)

	out5, ok := out4.(*ld.RDFDataset)
	require.True(t, ok, "%[1]T\n%[1]v", out4)

	return out5
}

func TestEntriesFromRDF(t *testing.T) {
	dataset := getDataset(t)

	entries, err := EntriesFromRDF(dataset)
	require.NoError(t, err)

	if false {
		for i, e := range entries {
			t.Logf("%2v: %v => %v", i, e.key, e.value)
		}
	}

	mkPath := func(parts ...interface{}) Path {
		p, err := NewPath(parts...)
		require.NoError(t, err)
		return p
	}

	wantEntries := []RDFEntry{
		{
			key: mkPath(
				"https://www.w3.org/2018/credentials#credentialSubject", 0,
				"http://schema.org/birthDate"),
			value: time.Date(1958, 7, 17, 0, 0, 0, 0, time.UTC),
		},
		{
			key: mkPath(
				"https://www.w3.org/2018/credentials#credentialSubject", 0,
				"http://schema.org/familyName"),
			value: "SMITH",
		},
		{
			key: mkPath(
				"https://www.w3.org/2018/credentials#credentialSubject", 0,
				"http://schema.org/gender"),
			value: "Male",
		},
		{
			key: mkPath(
				"https://www.w3.org/2018/credentials#credentialSubject", 0,
				"http://schema.org/givenName"),
			value: "JOHN",
		},
		{
			key: mkPath(
				"https://www.w3.org/2018/credentials#credentialSubject", 0,
				"http://schema.org/image"),
			value: "data:image/png;base64,iVBORw0KGgokJggg==",
		},
		{
			key: mkPath(
				"https://www.w3.org/2018/credentials#credentialSubject", 0,
				"http://www.w3.org/1999/02/22-rdf-syntax-ns#type", 0),
			value: "http://schema.org/Person",
		},
		{
			key: mkPath(
				"https://www.w3.org/2018/credentials#credentialSubject", 0,
				"http://www.w3.org/1999/02/22-rdf-syntax-ns#type", 1),
			value: "https://w3id.org/citizenship#PermanentResident",
		},
		{
			key: mkPath(
				"https://www.w3.org/2018/credentials#credentialSubject", 0,
				"https://w3id.org/citizenship#birthCountry"),
			value: "Bahamas",
		},
		{
			key: mkPath(
				"https://www.w3.org/2018/credentials#credentialSubject", 0,
				"https://w3id.org/citizenship#commuterClassification"),
			value: "C1",
		},
		{
			key: mkPath(
				"https://www.w3.org/2018/credentials#credentialSubject", 0,
				"https://w3id.org/citizenship#lprCategory"),
			value: "C09",
		},
		{
			key: mkPath(
				"https://www.w3.org/2018/credentials#credentialSubject", 0,
				"https://w3id.org/citizenship#lprNumber"),
			value: "999-999-999",
		},
		{
			key: mkPath(
				"https://www.w3.org/2018/credentials#credentialSubject", 0,
				"https://w3id.org/citizenship#residentSince"),
			value: time.Date(2015, 1, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			key: mkPath(
				"https://www.w3.org/2018/credentials#credentialSubject", 1,
				"http://schema.org/birthDate"),
			value: time.Date(1958, 7, 18, 0, 0, 0, 0, time.UTC),
		},
		{
			key: mkPath(
				"https://www.w3.org/2018/credentials#credentialSubject", 1,
				"http://schema.org/familyName"),
			value: "SMITH",
		},
		{
			key: mkPath(
				"https://www.w3.org/2018/credentials#credentialSubject", 1,
				"http://schema.org/gender"),
			value: "Male",
		},
		{
			key: mkPath(
				"https://www.w3.org/2018/credentials#credentialSubject", 1,
				"http://schema.org/givenName"),
			value: "JOHN",
		},
		{
			key: mkPath(
				"https://www.w3.org/2018/credentials#credentialSubject", 1,
				"http://schema.org/image"),
			value: "data:image/png;base64,iVBORw0KGgokJggg==",
		},
		{
			key: mkPath(
				"https://www.w3.org/2018/credentials#credentialSubject", 1,
				"http://www.w3.org/1999/02/22-rdf-syntax-ns#type", 0),
			value: "http://schema.org/Person",
		},
		{
			key: mkPath(
				"https://www.w3.org/2018/credentials#credentialSubject", 1,
				"http://www.w3.org/1999/02/22-rdf-syntax-ns#type", 1),
			value: "https://w3id.org/citizenship#PermanentResident",
		},
		{
			key: mkPath(
				"https://www.w3.org/2018/credentials#credentialSubject", 1,
				"https://w3id.org/citizenship#birthCountry"),
			value: "Bahamas",
		},
		{
			key: mkPath(
				"https://www.w3.org/2018/credentials#credentialSubject", 1,
				"https://w3id.org/citizenship#commuterClassification"),
			value: "C1",
		},
		{
			key: mkPath(
				"https://www.w3.org/2018/credentials#credentialSubject", 1,
				"https://w3id.org/citizenship#lprCategory"),
			value: "C09",
		},
		{
			key: mkPath(
				"https://www.w3.org/2018/credentials#credentialSubject", 1,
				"https://w3id.org/citizenship#lprNumber"),
			value: "999-999-999",
		},
		{
			key: mkPath(
				"https://www.w3.org/2018/credentials#credentialSubject", 1,
				"https://w3id.org/citizenship#residentSince"),
			value: time.Date(2015, 1, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			key:   mkPath("http://schema.org/description"),
			value: "Government of Example Permanent Resident Card.",
		},
		{
			key:   mkPath("http://schema.org/identifier"),
			value: int64(83627465),
		},
		{
			key:   mkPath("http://schema.org/name"),
			value: "Permanent Resident Card",
		},
		{
			key:   mkPath("http://www.w3.org/1999/02/22-rdf-syntax-ns#type", 0),
			value: "https://w3id.org/citizenship#PermanentResidentCard",
		},
		{
			key:   mkPath("http://www.w3.org/1999/02/22-rdf-syntax-ns#type", 1),
			value: "https://www.w3.org/2018/credentials#VerifiableCredential",
		},
		{
			key: mkPath("https://www.w3.org/2018/credentials#credentialSubject",
				0),
			value: "did:example:b34ca6cd37bbf23",
		},
		{
			key: mkPath("https://www.w3.org/2018/credentials#credentialSubject",
				1),
			value: "did:example:b34ca6cd37bbf24",
		},
		{
			key: mkPath("https://www.w3.org/2018/credentials#expirationDate"),
			//value: "2029-12-03T12:19:52Z",
			value: time.Date(2029, 12, 3, 12, 19, 52, 0, time.UTC),
		},
		{
			key: mkPath("https://www.w3.org/2018/credentials#issuanceDate"),
			//value: "2019-12-03T12:19:52Z",
			value: time.Date(2019, 12, 3, 12, 19, 52, 0, time.UTC),
		},
		{
			key:   mkPath("https://www.w3.org/2018/credentials#issuer"),
			value: "did:example:489398593",
		},
	}
	require.Equal(t, wantEntries, entries)
}

func TestProof(t *testing.T) {
	dataset := getDataset(t)

	entries, err := EntriesFromRDF(dataset)
	require.NoError(t, err)

	ctx := context.Background()

	mt, err := merkletree.NewMerkleTree(ctx, memory.NewMemoryStorage(), 40)
	require.NoError(t, err)

	err = AddEntriesToMerkleTree(ctx, mt, entries)
	require.NoError(t, err)

	// [https://www.w3.org/2018/credentials#credentialSubject 1 http://schema.org/birthDate] => 1958-07-18
	path, err := NewPath(
		"https://www.w3.org/2018/credentials#credentialSubject", 1,
		"http://schema.org/birthDate")
	require.NoError(t, err)

	birthDate := time.Date(1958, 7, 18, 0, 0, 0, 0, time.UTC)
	entry, err := NewRDFEntry(path, birthDate)
	require.NoError(t, err)

	key, val, err := entry.KeyValueHashes()
	require.NoError(t, err)

	p, _, err := mt.GenerateProof(ctx, key, nil)
	require.NoError(t, err)

	ok := merkletree.VerifyProof(mt.Root(), p, key, val)
	require.True(t, ok)
}

func TestProofInteger(t *testing.T) {
	dataset := getDataset(t)

	entries, err := EntriesFromRDF(dataset)
	require.NoError(t, err)

	ctx := context.Background()

	mt, err := merkletree.NewMerkleTree(ctx, memory.NewMemoryStorage(), 40)
	require.NoError(t, err)

	err = AddEntriesToMerkleTree(ctx, mt, entries)
	require.NoError(t, err)

	path, err := NewPath("http://schema.org/identifier")
	require.NoError(t, err)

	entry, err := NewRDFEntry(path, 83627465)
	require.NoError(t, err)

	key, val, err := entry.KeyValueHashes()
	require.NoError(t, err)

	p, _, err := mt.GenerateProof(ctx, key, nil)
	require.NoError(t, err)

	ok := merkletree.VerifyProof(mt.Root(), p, key, val)
	require.True(t, ok)
}

func TestMerklizer_Proof(t *testing.T) {
	ctx := context.Background()
	mz, err := Merklize(ctx, strings.NewReader(testDocument))
	require.NoError(t, err)

	t.Run("test with path as Path", func(t *testing.T) {
		// [https://www.w3.org/2018/credentials#credentialSubject 1 http://schema.org/birthDate] => 1958-07-18
		path, err := NewPath(
			"https://www.w3.org/2018/credentials#credentialSubject", 1,
			"http://schema.org/birthDate")
		require.NoError(t, err)

		p, path2, err := mz.Proof(ctx, path)
		require.NoError(t, err)

		pathKey, err := path.Key()
		require.NoError(t, err)

		pathKey2, err := path2.Key()
		require.NoError(t, err)

		require.True(t, pathKey2.Cmp(pathKey) == 0)

		birthDate := time.Date(1958, 7, 18, 0, 0, 0, 0, time.UTC)
		valueKey, err := mz.HashValue(birthDate)
		require.NoError(t, err)

		ok := merkletree.VerifyProof(mz.Root(), p, pathKey, valueKey)
		require.True(t, ok)
	})

	t.Run("test with path as shortcut string", func(t *testing.T) {
		p, path, err := mz.Proof(ctx, "credentialSubject.1.birthCountry")
		require.NoError(t, err)

		valueKey, err := mz.HashValue("Bahamas")
		require.NoError(t, err)

		pathKey, err := path.Key()
		require.NoError(t, err)

		ok := merkletree.VerifyProof(mz.Root(), p, pathKey, valueKey)
		require.True(t, ok)
	})

	mzRoot := mz.Root()
	require.Equal(t,
		"d001de1d1b74d3b24b394566511da50df18532264c473845ea51e915a588b02a",
		mzRoot.Hex())
}

func TestNewRelationship(t *testing.T) {
	iri := func(in string) ld.IRI {
		i := ld.NewIRI(in)
		return *i
	}
	nID := func(iri ld.IRI) nodeID {
		id, err := newNodeID(&iri)
		if err != nil {
			panic(err)
		}
		return id
	}
	dataset := getDataset(t)
	if false {
		logDataset(dataset)
	}

	rs, err := newRelationship(dataset.Graphs["@default"])
	require.NoError(t, err)
	wantRS := &relationship{
		parents: map[nodeID]quadKey{
			nID(iri("did:example:b34ca6cd37bbf23")): {
				subjectID: nID(iri("https://issuer.oidp.uscis.gov/credentials/83627465")),
				predicate: iri("https://www.w3.org/2018/credentials#credentialSubject"),
			},
			nID(iri("did:example:b34ca6cd37bbf24")): {
				subjectID: nID(iri("https://issuer.oidp.uscis.gov/credentials/83627465")),
				predicate: iri("https://www.w3.org/2018/credentials#credentialSubject"),
			},
		},
		children: map[nodeID][]nodeID{
			nID(iri("https://issuer.oidp.uscis.gov/credentials/83627465")): {
				nID(iri("did:example:b34ca6cd37bbf23")),
				nID(iri("did:example:b34ca6cd37bbf24")),
			},
		},
	}
	require.Equal(t, wantRS, rs)
}

func logDataset(in *ld.RDFDataset) {
	for s, gs := range in.Graphs {
		fmt.Printf("[6] %v: %v\n", s, len(gs))
		for i, g := range gs {
			subject := "nil"
			if g.Subject != nil {
				subject = g.Subject.GetValue()
			}
			predicate := "nil"
			if g.Predicate != nil {
				predicate = g.Predicate.GetValue()
			}
			object := "nil"
			var ol2 string
			ol, olOK := g.Object.(*ld.Literal)
			if olOK {
				ol2 = ol.Datatype
			}

			if g.Object != nil {
				object = g.Object.GetValue()
			}
			graph := "nil"
			if g.Graph != nil {
				graph = g.Graph.GetValue()
			}
			fmt.Printf(`[7] %v:
	Subject [%T]: %v
	Predicate [%T]: %v
	Object [%T]: %v %v
	Graph [%T]: %v
`, i,
				g.Subject, subject,
				g.Predicate, predicate,
				g.Object, object, ol2,
				g.Graph, graph)
		}
	}
}

func TestPathFromContext(t *testing.T) {
	// this file downloaded from here: https://www.w3.org/2018/credentials/v1
	ctxBytes, err := os.ReadFile("testdata/credentials_v1.json")
	require.NoError(t, err)

	in := "VerifiableCredential.credentialSchema.JsonSchemaValidator2018"
	result, err := NewPathFromContext(ctxBytes, in)
	require.NoError(t, err)

	want, err := NewPath(
		"https://www.w3.org/2018/credentials#VerifiableCredential",
		"https://www.w3.org/2018/credentials#credentialSchema",
		"https://www.w3.org/2018/credentials#JsonSchemaValidator2018")
	require.NoError(t, err)

	require.Equal(t, want, result)
}

func TestPathFromDocument(t *testing.T) {
	in := "credentialSubject.1.birthDate"
	result, err := NewPathFromDocument([]byte(testDocument), in)
	require.NoError(t, err)

	want, err := NewPath(
		"https://www.w3.org/2018/credentials#credentialSubject",
		1,
		"http://schema.org/birthDate")
	require.NoError(t, err)

	require.Equal(t, want, result)
}

func TestMkValueInt(t *testing.T) {
	testCases := []struct {
		in   int64
		want string
	}{
		{
			in:   -1,
			want: "21888242871839275222246405745257275088548364400416034343698204186575808495616",
		},
		{
			in:   -2,
			want: "21888242871839275222246405745257275088548364400416034343698204186575808495615",
		},
		{
			in:   math.MinInt64,
			want: "21888242871839275222246405745257275088548364400416034343688980814538953719809",
		},
	}
	for i := range testCases {
		tc := testCases[i]
		t.Run(fmt.Sprintf("#%v", i+1), func(t *testing.T) {
			v, err := mkValueInt(defaultHasher, tc.in)
			require.NoError(t, err)
			require.Equal(t, tc.want, v.Text(10))
		})
	}

	t.Run("int value", func(t *testing.T) {
		v, err := mkValueInt(defaultHasher, int(math.MinInt64))
		require.NoError(t, err)
		require.Equal(t,
			"21888242871839275222246405745257275088548364400416034343688980814538953719809",
			v.Text(10))
	})
}

func TestXX1(t *testing.T) {
	t.Skip("not ready")
	in := `{
    "@context": "https://schema.org",
    "@type": "Person",
    "address": {
        "@type": "PostalAddress",
        "addressLocality": "Colorado Springs",
        "addressRegion": "CO",
        "postalCode": "80840",
        "streetAddress": "100 Main Street"
    },
    "colleague": [
        "http://www.example.com/JohnColleague.html",
        "http://www.example.com/JameColleague.html"
    ],
    "email": "info@example.com",
    "name": "Jane Doe",
    "alumniOf": "Dartmouth",
    "birthDate": "1979-10-12"
}`
	var obj map[string]interface{}
	err := json.Unmarshal([]byte(in), &obj)
	if err != nil {
		panic(err)
	}

	proc := ld.NewJsonLdProcessor()
	options := ld.NewJsonLdOptions("")
	options.Algorithm = "URDNA2015"

	out4, err := proc.Normalize(obj, options)
	require.NoError(t, err)

	out5, ok := out4.(*ld.RDFDataset)
	require.True(t, ok, "%[1]T\n%[1]v", out4)

	quads := out5.Graphs["@default"]
	for i, q := range quads {
		t.Logf(`#%[1]v
Subject: %[2]T %[2]v
Predicate: %[3]T %[3]v
Object: %[4]T %[4]v
Graph: %[5]T %[5]v`,
			i, q.Subject, q.Predicate, q.Object, q.Graph)
	}

	entries, err := EntriesFromRDF(out5)
	require.NoError(t, err)

	for _, e := range entries {
		t.Logf("%v => %v", e.key, e.value)
	}
}

func TestXX2(t *testing.T) {
	t.Skip("not ready")
	var ctxObj map[string]interface{}
	err := json.Unmarshal([]byte(testDocument), &ctxObj)
	require.NoError(t, err)
	t.Log(ctxObj["@context"])
	activeCtx := ld.NewContext(nil, nil)
	newCtx, err := activeCtx.Parse(ctxObj["@context"])
	require.NoError(t, err)
	td := newCtx.GetTermDefinition("type")
	t.Log(td)
}
