package merklize

import (
	"context"
	"errors"
	"fmt"
	"math/big"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-merkletree-sql"
	"github.com/piprate/json-gold/ld"
)

type entryKey2 []interface{}

type entry2 struct {
	key   entryKey2
	value string
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

func (r *relationship) path(n *ld.Quad, idx *int) (entryKey2, error) {
	var k []interface{}

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

	reverse(k)
	return k, nil
}

func reverse(s []interface{}) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}

// EntriesFromRDF creates entries from RDF dataset suitable to add to
// merkle tree
func EntriesFromRDF(ds *ld.RDFDataset) ([]entry2, error) {
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

	//parents, err := findDependencies(quads)
	//if err != nil {
	//	return nil, err
	//}

	entries := make([]entry2, len(quads))
	for i, q := range quads {
		switch qo := q.Object.(type) {
		case *ld.IRI, *ld.Literal:
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
	entries []entry2) error {

	for _, e := range entries {
		key, err := mkKey(e.key)
		if err != nil {
			return err
		}

		val, err := mkValueString(e.value)
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

// keyParts is an array of json key parts: either string or int (object key
// or array index)
func mkKey(keyParts []interface{}) (*big.Int, error) {
	var err error
	intKeyParts := make([]*big.Int, len(keyParts))
	for i := range keyParts {
		switch v := keyParts[i].(type) {
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

func mkValueString(val string) (*big.Int, error) {
	return poseidon.HashBytes([]byte(val))
}
