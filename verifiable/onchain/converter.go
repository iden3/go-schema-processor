package onchain

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-schema-processor/v2/merklize"
	"github.com/iden3/go-schema-processor/v2/verifiable"
	"github.com/piprate/json-gold/ld"
)

type Convertor struct {
	marklizeInstance merklize.Options

	id string
}

type ConvertorOption func(*Convertor)

// WithID sets custom id for the credential.
func WithID(id string) ConvertorOption {
	return func(p *Convertor) {
		p.id = id
	}
}

// WithMerklizerOptions sets options for merklizer.
func WithMerklizerOptions(m merklize.Options) ConvertorOption {
	return func(p *Convertor) {
		p.marklizeInstance = m
	}
}

func NewParser(opts ...ConvertorOption) *Convertor {
	p := &Convertor{}

	for _, opt := range opts {
		opt(p)
	}

	return p
}

// ConvertVerifiableCredential converts an onchain verifiable credential to a W3C verifiable credential.
// The w3c credential id will be regenerated.
func ConvertVerifiableCredential(credential *Credential) (*verifiable.W3CCredential, error) {
	id := fmt.Sprintf("urn:uuid:%s", uuid.NewString())
	return (&Convertor{id: id}).ConvertVerifiableCredential(credential)
}

// ConvertVerifiableCredential converts an onchain verifiable credential to a W3C verifiable credential.
func (p *Convertor) ConvertVerifiableCredential(onchainCredential *Credential) (*verifiable.W3CCredential, error) {
	timestampExp, err := strconv.ParseInt(onchainCredential.Expiration, 10, 64)
	if err != nil {
		return nil,
			fmt.Errorf("failed to parse Expiration '%s': %w", onchainCredential.Expiration, err)
	}
	timestampIssuance, err := strconv.ParseInt(onchainCredential.IssuanceDate, 10, 64)
	if err != nil {
		return nil,
			fmt.Errorf("failed to parse IssuanceDate '%s': %w", onchainCredential.IssuanceDate, err)
	}
	expirationTime := time.Unix(timestampExp, 0).UTC()
	issuanceTime := time.Unix(timestampIssuance, 0).UTC()

	// build issuer DID
	issuerBI, ok := big.NewInt(0).SetString(onchainCredential.Issuer, 10)
	if !ok {
		return nil,
			fmt.Errorf("failed to convert issuer '%s' to BigInt: %w", onchainCredential.Issuer, err)
	}
	issuerDID, err := bigIntToDID(issuerBI)
	if err != nil {
		return nil,
			fmt.Errorf("failed to extract issuer DID: %w", err)
	}

	credentialStatus, err := p.convertCredentialStatus(
		issuerDID,
		onchainCredential.CredentialStatus,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to convert CredentialStatus: %w", err)
	}

	credentialSubject, err := p.convertCredentialSubject(onchainCredential)
	if err != nil {
		return nil, fmt.Errorf("failed to convert CredentialSubject: %w", err)
	}

	mtpProof, err := p.convertMtpProof(issuerDID, onchainCredential.Proof[0])
	if err != nil {
		return nil, fmt.Errorf("failed to convert MTPProof: %w", err)
	}

	id, err := p.convertCredentialID(onchainCredential.ID)
	if err != nil {
		return nil, err
	}
	return &verifiable.W3CCredential{
		ID:      id,
		Context: onchainCredential.Context,
		Type:    onchainCredential.Type,
		CredentialSchema: verifiable.CredentialSchema{
			ID:   onchainCredential.CredentialSchema.ID,
			Type: onchainCredential.CredentialSchema.Type,
		},
		Expiration:        &expirationTime,
		IssuanceDate:      &issuanceTime,
		Issuer:            issuerDID.String(),
		CredentialStatus:  credentialStatus,
		CredentialSubject: credentialSubject,
		Proof:             verifiable.CredentialProofs{mtpProof},
	}, nil
}

func (p *Convertor) convertCredentialID(id string) (string, error) {
	if p.id != "" {
		id = p.id
	}
	_, err := url.ParseRequestURI(id)
	if err != nil {
		return "", fmt.Errorf("id '%s' should be valid URI: %w", id, err)
	}
	return id, nil
}

func (p *Convertor) convertCredentialStatus(
	issuerDID *w3c.DID,
	credentialStatus CredentialStatus,
) (*verifiable.CredentialStatus, error) {
	switch verifiable.CredentialStatusType(credentialStatus.Type) {
	case verifiable.Iden3OnchainSparseMerkleTreeProof2023:
		nonce, err := strconv.ParseUint(credentialStatus.RevocationNonce, 10, 64)
		if err != nil {
			return nil,
				fmt.Errorf("invalid revocationNonce '%s': %w", credentialStatus.RevocationNonce, err)
		}

		chainID, err := core.ChainIDfromDID(*issuerDID)
		if err != nil {
			return nil,
				fmt.Errorf("failed to extract chainID from DID: %w", err)
		}
		issuerID, err := core.IDFromDID(*issuerDID)
		if err != nil {
			return nil,
				fmt.Errorf("failed to extract ID from DID: %w", err)
		}
		contractAddress, err := core.EthAddressFromID(issuerID)
		if err != nil {
			return nil,
				fmt.Errorf("failed to extract contract address from ID: %w", err)
		}
		contractID := fmt.Sprintf("%d:0x%s", chainID, hex.EncodeToString(contractAddress[:]))

		return &verifiable.CredentialStatus{
			ID: fmt.Sprintf(
				"%s%s?revocationNonce=%d&contractAddress=%s",
				issuerDID.String(),
				credentialStatus.ID,
				nonce,
				contractID,
			),
			Type:            verifiable.Iden3OnchainSparseMerkleTreeProof2023,
			RevocationNonce: nonce,
		}, nil
	default:
		return nil,
			fmt.Errorf("unsupported CredentialStatus type: %s", credentialStatus.Type)
	}

}

func extractCredentialType(types []string) (string, error) {
	if len(types) != 2 {
		return "", fmt.Errorf("credential should have exactly two types")
	}

	switch {
	case types[0] == verifiableCredentialType:
		return types[1], nil
	case types[1] == verifiableCredentialType:
		return types[0], nil
	default:
		return "", fmt.Errorf("credential type is invalid")
	}
}

func (p *Convertor) convertCredentialSubject(onchainCredential *Credential) (map[string]any, error) {
	var (
		idIsSet bool

		credentialSubject = make(map[string]any)
	)

	contextbytes, err := json.Marshal(map[string][]string{
		"@context": onchainCredential.Context,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal context: %w", err)
	}

	credentialType, err := extractCredentialType(onchainCredential.Type)
	if err != nil {
		return nil, fmt.Errorf("failed to extract credential type: %w", err)
	}

	for _, f := range onchainCredential.CredentialSubject {
		switch f.Key {
		case reservedCredentialSubjectKeyID:
			idIsSet = true
			ownderID, ok := big.NewInt(0).SetString(f.Value, 10)
			if !ok {
				return nil,
					fmt.Errorf("failed to extract ownerID '%s' from CredentialSubject", f.Value)
			}
			ownerDID, err := bigIntToDID(ownderID)
			if err != nil {
				return nil,
					fmt.Errorf("failed to convert ownerID '%s' to DID: %w", f.Value, err)
			}
			credentialSubject["id"] = ownerDID.String()
			continue
		case reservedCredentialSubjectKeyType:
			hexBytes, err := hex.DecodeString(hexWithoutPrefix(f.RawValue))
			if err != nil {
				return nil,
					fmt.Errorf("failed to decode hex '%s' from CredentialSubject: %w", f.RawValue, err)
			}
			credentialSubject["type"] = string(hexBytes)
			continue
		}

		datatype, err := p.marklizeInstance.TypeFromContext(
			contextbytes,
			fmt.Sprintf("%s.%s", credentialType, f.Key),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to extract type for field '%s': %w", f.Key, err)
		}

		switch datatype {
		case ld.XSDBoolean:
			switch f.Value {
			case booleanHashTrue:
				credentialSubject[f.Key] = true
			case booleanHashFalse:
				credentialSubject[f.Key] = false
			default:
				return nil, fmt.Errorf("unsupported boolean value: %s", f.Value)
			}
		case ld.XSDNS + "positiveInteger",
			ld.XSDNS + "nonNegativeInteger",
			ld.XSDNS + "negativeInteger",
			ld.XSDNS + "nonPositiveInteger":
			bi, ok := new(big.Int).SetString(f.Value, 10)
			if !ok {
				return nil,
					fmt.Errorf("failed to convert string '%s' to BigInt", f.Value)
			}
			credentialSubject[f.Key] = bi.String()
		case ld.XSDInteger:
			v, err := strconv.ParseInt(f.Value, 10, 64)
			if err != nil {
				return nil,
					fmt.Errorf("failed to convert string '%s' to int: %w", f.Value, err)
			}
			credentialSubject[f.Key] = v
		case ld.XSDString:
			strBytes, err := hex.DecodeString(hexWithoutPrefix(f.RawValue))
			if err != nil {
				return nil,
					fmt.Errorf("failed to decode hex '%s' from CredentialSubject: %w", f.RawValue, err)
			}
			source := string(strBytes)
			if err := validateSourceValue(datatype, f.Value, source); err != nil {
				return nil, err
			}
			credentialSubject[f.Key] = source
		case ld.XSDNS + "dateTime":
			timestamp, ok := big.NewInt(0).SetString(hexWithoutPrefix(f.RawValue), 16)
			if !ok {
				return nil,
					fmt.Errorf("failed to convert string '%s' to BigInt", f.RawValue)
			}
			sourceTime := time.Unix(
				timestamp.Int64(),
				0,
			).UTC().Format(time.RFC3339Nano)
			if err := validateSourceValue(datatype, f.Value, sourceTime); err != nil {
				return nil, err
			}
			credentialSubject[f.Key] = sourceTime
		case ld.XSDDouble:
			v, _, err := big.NewFloat(0).Parse(hexWithoutPrefix(f.RawValue), 16)
			if err != nil {
				return nil,
					fmt.Errorf("failed to convert string '%s' to float", f.RawValue)
			}
			sourceDouble, _ := v.Float64()
			if err := validateSourceValue(datatype, f.Value, sourceDouble); err != nil {
				return nil, err
			}
			credentialSubject[f.Key] = sourceDouble
		default:
			return nil, fmt.Errorf("unsupported type: %s", datatype)
		}
	}

	if !idIsSet {
		return nil, fmt.Errorf("CredentialSubject does not have required fields: '%s", reservedCredentialSubjectKeyID)
	}

	return credentialSubject, nil
}

func (p *Convertor) convertMtpProof(
	issuerDID *w3c.DID,
	issuanceProof Proof,
) (*verifiable.Iden3SparseMerkleTreeProof, error) {
	var biCoreClaim [8]*big.Int
	for i, s := range issuanceProof.CoreClaim {
		bi, ok := new(big.Int).SetString(s, 10)
		if !ok {
			return nil,
				fmt.Errorf("failed to convert string '%s' to BigInt", s)
		}
		biCoreClaim[i] = bi
	}
	coreClaim, err := core.NewClaimFromBigInts(biCoreClaim)
	if err != nil {
		return nil, fmt.Errorf("failed to create core claim: %w", err)
	}

	mtp, err := convertChainProofToMerkleProof(&issuanceProof.MTP)
	if err != nil {
		return nil, fmt.Errorf("failed to convert chain proof to merkle proof: %w", err)
	}

	coreClaimHex, err := coreClaim.Hex()
	if err != nil {
		return nil, fmt.Errorf("failed to convert CoreClaim to hex: %w", err)
	}

	rootOfRoots, err := merkletree.NewHashFromString(issuanceProof.IssuerData.State.RootOfRoots)
	if err != nil {
		return nil,
			fmt.Errorf("failed to convert RootOfRoots '%s' to hash: %w", issuanceProof.IssuerData.State.RootOfRoots, err)
	}
	claimsTreeRoot, err := merkletree.NewHashFromString(issuanceProof.IssuerData.State.ClaimsTreeRoot)
	if err != nil {
		return nil,
			fmt.Errorf("failed to convert ClaimsTreeRoot '%s' to hash: %w", issuanceProof.IssuerData.State.ClaimsTreeRoot, err)
	}
	revocationTreeRoot, err := merkletree.NewHashFromString(issuanceProof.IssuerData.State.RevocationTreeRoot)
	if err != nil {
		return nil,
			fmt.Errorf("failed to convert RevocationTreeRoot '%s' to hash: %w", issuanceProof.IssuerData.State.RevocationTreeRoot, err)
	}
	value, err := merkletree.NewHashFromString(issuanceProof.IssuerData.State.Value)
	if err != nil {
		return nil,
			fmt.Errorf("failed to convert Value '%s' to hash: %w", issuanceProof.IssuerData.State.Value, err)
	}
	mtpProof := verifiable.Iden3SparseMerkleTreeProof{
		Type: verifiable.ProofType(issuanceProof.Type),
		IssuerData: verifiable.IssuerData{
			ID: issuerDID.String(),
			State: verifiable.State{
				RootOfRoots:        strPtr(rootOfRoots.Hex()),
				ClaimsTreeRoot:     strPtr(claimsTreeRoot.Hex()),
				RevocationTreeRoot: strPtr(revocationTreeRoot.Hex()),
				Value:              strPtr(value.Hex()),
			},
		},
		CoreClaim: coreClaimHex,
		MTP:       mtp,
	}

	return &mtpProof, nil
}

func bigIntToDID(bi *big.Int) (*w3c.DID, error) {
	id, err := core.IDFromInt(bi)
	if err != nil {
		return nil,
			fmt.Errorf("failed to convert BigInt '%s' to ID: %w", bi.String(), err)
	}
	did, err := core.ParseDIDFromID(id)
	if err != nil {
		return nil,
			fmt.Errorf("failed to convert ID to DID: %w", err)
	}
	return did, nil
}

func strPtr(s string) *string {
	return &s
}

func validateSourceValue(datatype, origin string, source any) error {
	sourceHash, err := merklize.HashValue(datatype, source)
	if err != nil {
		return fmt.Errorf("failed hash value '%s' with data type '%s': %w", source, datatype, err)
	}
	originHash, ok := big.NewInt(0).SetString(origin, 10)
	if !ok {
		return fmt.Errorf("invalid origin '%s'", origin)
	}
	if sourceHash.Cmp(originHash) != 0 {
		return fmt.Errorf("hash of value '%s' does not match core claim value '%s'", sourceHash, originHash)
	}
	return nil
}

func convertChainProofToMerkleProof(proof *MTP) (*merkletree.Proof, error) {
	var (
		existence bool
		nodeAux   *merkletree.NodeAux
		err       error
	)

	if proof.Existence {
		existence = true
	} else {
		existence = false
		if proof.AuxExistence {
			nodeAux = &merkletree.NodeAux{}
			nodeAux.Key, err = merkletree.NewHashFromString(proof.AuxIndex)
			if err != nil {
				return nil, err
			}
			nodeAux.Value, err = merkletree.NewHashFromString(proof.AuxValue)
			if err != nil {
				return nil, err
			}
		}
	}

	allSiblings := make([]*merkletree.Hash, len(proof.Siblings))
	for i, s := range proof.Siblings {
		var sh *merkletree.Hash
		sh, err = merkletree.NewHashFromString(s)
		if err != nil {
			return nil, err
		}
		allSiblings[i] = sh
	}

	p, err := merkletree.NewProofFromData(existence, allSiblings, nodeAux)
	if err != nil {
		return nil, err
	}

	return p, nil
}

func hexWithoutPrefix(s string) string {
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		return s[2:]
	}
	return s
}
