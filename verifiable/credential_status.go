package verifiable

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/pkg/errors"
)

var ErrCredentialIsRevoked = errors.New("credential is revoked")

// TODO: Many be it would be reasonable to accept Registry optionaly and use global one (default) is not passed.
//       Issuser DID  & user DID may be passed as options as well. I'm not sure for now how to use them.

// ValidateCredentialStatus resolves the credential status (possibly download
// proofs from outer world) and validates the proof. May return
// ErrCredentialIsRevoked if the credential was revoked.
func ValidateCredentialStatus(ctx context.Context, credStatus any,
	revNonce uint64,
	credStatusResolverRegistry *CredentialStatusResolverRegistry,
	issuerDID, userDID *w3c.DID) (RevocationStatus, error) {

	revocationStatus, err := resolveRevStatus(ctx, credStatus,
		credStatusResolverRegistry, issuerDID, userDID)
	if err != nil {
		return revocationStatus, err
	}
	treeStateOk, err := validateTreeState(revocationStatus.Issuer)
	if err != nil {
		return revocationStatus, err
	}
	if !treeStateOk {
		return revocationStatus, errors.New("signature proof: invalid tree state of the issuer while checking credential status of singing key")
	}

	revocationRootHash := &merkletree.HashZero
	if revocationStatus.Issuer.RevocationTreeRoot != nil {
		revocationRootHash, err = merkletree.NewHashFromHex(*revocationStatus.Issuer.RevocationTreeRoot)
		if err != nil {
			return revocationStatus, err
		}
	}

	proofValid := merkletree.VerifyProof(revocationRootHash,
		&revocationStatus.MTP, new(big.Int).SetUint64(revNonce), big.NewInt(0))
	if !proofValid {
		return revocationStatus, fmt.Errorf("proof validation failed. revNonce=%d", revNonce)
	}

	if revocationStatus.MTP.Existence {
		return revocationStatus, ErrCredentialIsRevoked
	}

	return revocationStatus, nil
}

func resolveRevStatus(ctx context.Context, status any,
	credStatusResolverRegistry *CredentialStatusResolverRegistry,
	issuerDID, userDID *w3c.DID) (out RevocationStatus, err error) {

	var statusType CredentialStatusType
	var credentialStatusTyped CredentialStatus

	switch status := status.(type) {
	case *CredentialStatus:
		statusType = status.Type
		credentialStatusTyped = *status
	case CredentialStatus:
		statusType = status.Type
		credentialStatusTyped = status
	case jsonObj:
		credStatusType, ok := status["type"].(string)
		if !ok {
			return out,
				errors.New("credential status doesn't contain type")
		}
		statusType = CredentialStatusType(credStatusType)
		err = remarshalObj(&credentialStatusTyped, status)
		if err != nil {
			return out, err
		}
	default:
		return out,
			errors.New("unknown credential status format")
	}

	resolver, err := credStatusResolverRegistry.Get(statusType)
	if err != nil {
		return out, err
	}

	// TODO do we need this here or we should delegate it to the upper level?
	ctx = WithIssuerDID(ctx, issuerDID)
	ctx = WithUserDID(ctx, userDID)
	return resolver.Resolve(ctx, credentialStatusTyped)
}

// marshal/unmarshal object from one type to other
func remarshalObj(dst, src any) error {
	objBytes, err := json.Marshal(src)
	if err != nil {
		return err
	}
	return json.Unmarshal(objBytes, dst)
}

// check Issuer TreeState consistency
func validateTreeState(i Issuer) (bool, error) {
	if i.State == nil {
		return false, errors.New("state is nil")
	}

	var err error
	ctrHash := &merkletree.HashZero
	if i.ClaimsTreeRoot != nil {
		ctrHash, err = merkletree.NewHashFromHex(*i.ClaimsTreeRoot)
		if err != nil {
			return false, err
		}
	}
	rtrHash := &merkletree.HashZero
	if i.RevocationTreeRoot != nil {
		rtrHash, err = merkletree.NewHashFromHex(*i.RevocationTreeRoot)
		if err != nil {
			return false, err
		}
	}
	rorHash := &merkletree.HashZero
	if i.RootOfRoots != nil {
		rorHash, err = merkletree.NewHashFromHex(*i.RootOfRoots)
		if err != nil {
			return false, err
		}
	}

	wantState, err := poseidon.Hash([]*big.Int{ctrHash.BigInt(),
		rtrHash.BigInt(), rorHash.BigInt()})
	if err != nil {
		return false, err
	}

	stateHash, err := merkletree.NewHashFromHex(*i.State)
	if err != nil {
		return false, err
	}
	return wantState.Cmp(stateHash.BigInt()) == 0, nil
}