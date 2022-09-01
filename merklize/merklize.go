package merklize

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strconv"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-merkletree-sql"
	"github.com/piprate/json-gold/ld"
)

type Path []interface{}

func (p Path) reverse() {
	for i, j := 0, len(p)-1; i < j; i, j = i+1, j-1 {
		p[i], p[j] = p[j], p[i]
	}
}

func (p Path) Key() (*big.Int, error) {
	var err error
	intKeyParts := make([]*big.Int, len(p))
	for i := range p {
		switch v := p[i].(type) {
		case string:
			intKeyParts[i], err = poseidon.HashBytes([]byte(v))
			if err != nil {
				return nil, err
			}
		case int:
			intKeyParts[i] = big.NewInt(int64(v))
		default:
			return nil, fmt.Errorf("unexpected type %T", v)
		}
	}

	return poseidon.Hash(intKeyParts)
}

type RDFEntry struct {
	key Path
	// valid types are: int64, string, bool
	value interface{}
}

func NewRDFEntry(key Path, value interface{}) (RDFEntry, error) {
	e := RDFEntry{key: key}
	if len(key) == 0 {
		return e, errors.New("key length is zero")
	}

	switch v := value.(type) {
	case int:
		e.value = int64(v)
	case int64, string, bool:
		e.value = value
	default:
		return e, fmt.Errorf("incorrect value type: %T", value)
	}

	return e, nil
}

func (e RDFEntry) KeyHash() (*big.Int, error) {
	return e.key.Key()
}

func (e RDFEntry) ValueHash() (*big.Int, error) {
	switch et := e.value.(type) {
	case int64:
		return mkValueInt(et)
	case bool:
		return mkValueBool(et)
	case string:
		return mkValueString(et)
	default:
		return nil, fmt.Errorf("unexpected value type: %T", e.value)
	}
}

func (e RDFEntry) KeyValueHashes() (
	keyHash *big.Int, valueHash *big.Int, err error) {

	keyHash, err = e.KeyHash()
	if err != nil {
		return nil, nil, err
	}

	valueHash, err = e.ValueHash()
	if err != nil {
		return nil, nil, err
	}

	return keyHash, valueHash, nil
}

type quadKey struct {
	subject   ld.IRI
	predicate ld.IRI
}

type relationship struct {
	// mapping from child Subject to its parent
	parents map[ld.IRI]quadKey
	// mapping from parent to array of children
	children map[ld.IRI][]ld.IRI
}

func newRelationship(quads []*ld.Quad) (*relationship, error) {
	r := relationship{
		parents:  make(map[ld.IRI]quadKey),
		children: make(map[ld.IRI][]ld.IRI),
	}

	subjectSet := make(map[ld.IRI]struct{})
	for _, q := range quads {
		switch s := q.Subject.(type) {
		case *ld.IRI:
			if s == nil {
				return nil, errors.New("subject is nil")
			}
			subjectSet[*s] = struct{}{}
		case *ld.BlankNode:
			return nil, errors.New("[2] BlankNode is not supported yet")
		default:
			continue
		}
	}

	for _, q := range quads {
		objIRI, ok := q.Object.(*ld.IRI)
		if !ok || objIRI == nil {
			continue
		}

		_, ok = subjectSet[*objIRI]
		if !ok {
			continue
		}

		qk, err := getQuadKey(q)
		if err != nil {
			return nil, err
		}
		r.parents[*objIRI] = qk

		r.children[qk.subject] = append(r.children[qk.subject], *objIRI)
	}

	return &r, nil
}

func (r *relationship) path(n *ld.Quad, idx *int) (Path, error) {
	var k Path

	if n == nil {
		return nil, errors.New("quad is nil")
	}

	var subject ld.IRI
	switch qs := n.Subject.(type) {
	case *ld.IRI:
		if qs == nil {
			return nil, errors.New("subject IRI is nil")
		}
		subject = *qs
	case *ld.BlankNode:
		return nil, errors.New("[3] BlankNode is not supported yet")
	default:
		return nil, errors.New("unexpected Quad's Subject type")
	}

	var predicate ld.IRI
	switch qp := n.Predicate.(type) {
	case *ld.IRI:
		if qp == nil {
			return nil, errors.New("predicate IRI is nil")
		}
		predicate = *qp
	default:
		return nil, errors.New("unexpected Quad's Predicate type")
	}

	if idx != nil {
		k = append(k, *idx)
	}
	k = append(k, predicate.Value)
	nextKey := subject
	for {
		parent, ok := r.parents[nextKey]
		if !ok {
			break
		}

		children, ok := r.children[parent.subject]
		if !ok {
			return nil, errors.New("[assertion] parent not found in children")
		}

		if len(children) == 1 {
			k = append(k, parent.predicate.Value)
		} else {
			found := false
			for i, child := range children {
				if child.Value == nextKey.Value {
					found = true
					k = append(k, i, parent.predicate.Value)
					break
				}
			}
			if !found {
				return nil, errors.New(
					"[assertion] child not found in parent's relations")
			}
		}

		nextKey = parent.subject
	}

	k.reverse()
	return k, nil
}

// EntriesFromRDF creates entries from RDF dataset suitable to add to
// merkle tree
func EntriesFromRDF(ds *ld.RDFDataset) ([]RDFEntry, error) {
	if len(ds.Graphs) != 1 {
		return nil, errors.New("support only dataset with one @default graph")
	}

	quads, ok := ds.Graphs["@default"]
	if !ok {
		return nil, errors.New("@default graph not found in dataset")
	}

	counts, err := countEntries(quads)
	if err != nil {
		return nil, err
	}

	seenCount := make(map[quadKey]int)

	rs, err := newRelationship(quads)
	if err != nil {
		return nil, err
	}

	entries := make([]RDFEntry, len(quads))
	for i, q := range quads {
		switch qo := q.Object.(type) {
		case *ld.Literal:
			if qo == nil {
				return nil, errors.New("object Literal is nil")
			}
			switch qo.Datatype {
			case "http://www.w3.org/2001/XMLSchema#boolean":
				switch qo.Value {
				case "false":
					entries[i].value = false
				case "true":
					entries[i].value = true
				default:
					return nil, errors.New("incorrect boolean value")
				}
			case "http://www.w3.org/2001/XMLSchema#integer",
				"http://www.w3.org/2001/XMLSchema#nonNegativeInteger",
				"http://www.w3.org/2001/XMLSchema#nonPositiveInteger",
				"http://www.w3.org/2001/XMLSchema#negativeInteger",
				"http://www.w3.org/2001/XMLSchema#positiveInteger":
				entries[i].value, err = strconv.ParseInt(qo.Value, 10, 64)
				if err != nil {
					return nil, err
				}
			default:
				entries[i].value = qo.GetValue()
			}
		case *ld.IRI:
			if qo == nil {
				return nil, errors.New("object IRI is nil")
			}
			entries[i].value = qo.GetValue()
		case *ld.BlankNode:
			return nil, errors.New("[1] BlankNode is not supported yet")
		default:
			return nil, errors.New("unexpected Quad's Object type")
		}

		qKey, err := getQuadKey(q)
		if err != nil {
			return nil, err
		}

		var idx *int
		switch counts[qKey] {
		case 0:
			return nil, errors.New("[assertion] key not found in counts")
		case 1:
			// leave idx nil: only one element, do not consider it as an array
		default:
			idx = new(int)
			*idx = seenCount[qKey]
			seenCount[qKey]++
		}
		entries[i].key, err = rs.path(q, idx)
		if err != nil {
			return nil, err
		}
	}

	return entries, nil
}

// count number of entries with same key to distinguish between plain values
// and arrays (sets)
func countEntries(nodes []*ld.Quad) (map[quadKey]int, error) {
	res := make(map[quadKey]int, len(nodes))
	for _, q := range nodes {
		key, err := getQuadKey(q)
		if err != nil {
			return nil, err
		}
		res[key]++
	}
	return res, nil
}

func getQuadKey(q *ld.Quad) (quadKey, error) {
	var key quadKey

	if q == nil {
		return key, errors.New("quad is nil")
	}

	subject, ok := q.Subject.(*ld.IRI)
	if !ok || subject == nil {
		return key, errors.New("subject is not of IRI type or nil")
	}
	key.subject = *subject

	predicate, ok := q.Predicate.(*ld.IRI)
	if !ok || predicate == nil {
		return key, errors.New("predicate is not of IRI type or nil")
	}
	key.predicate = *predicate

	return key, nil
}

func AddEntriesToMerkleTree(ctx context.Context, mt *merkletree.MerkleTree,
	entries []RDFEntry) error {

	for _, e := range entries {
		key, val, err := e.KeyValueHashes()
		if err != nil {
			return err
		}

		err = mt.Add(ctx, key, val)
		if err != nil {
			return err
		}
	}

	return nil
}

func mkValueString(val string) (*big.Int, error) {
	return poseidon.HashBytes([]byte(val))
}

func mkValueBool(val bool) (*big.Int, error) {
	if val {
		return poseidon.Hash([]*big.Int{big.NewInt(1)})
	} else {
		return poseidon.Hash([]*big.Int{big.NewInt(0)})
	}
}

func mkValueInt(val int64) (*big.Int, error) {
	return poseidon.Hash([]*big.Int{big.NewInt(val)})
}
