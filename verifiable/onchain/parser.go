package onchain

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
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

type Parser struct {
	marklizeInstance merklize.Options

	regenerateID bool
}

type Option func(*Parser)

// WithRegenerateID sets the regenerateID flag to the given value.
func WithRegenerateID(regenerateID bool) Option {
	return func(p *Parser) {
		p.regenerateID = regenerateID
	}
}

// WithMerklizer sets the merklizer instance.
func WithMerklizer(m merklize.Options) Option {
	return func(p *Parser) {
		p.marklizeInstance = m
	}
}

func NewParser(opts ...Option) *Parser {
	p := &Parser{
		regenerateID: false,
	}

	for _, opt := range opts {
		opt(p)
	}

	return p
}

// ConvertVerifiableCredential converts an onchain verifiable credential to a W3C verifiable credential.
// The w3c credential id will be regenerated.
func ConvertVerifiableCredential(credential *Credential) (*verifiable.W3CCredential, error) {
	return (&Parser{regenerateID: true}).ConvertVerifiableCredential(credential)
}

// ConvertVerifiableCredential converts an onchain verifiable credential to a W3C verifiable credential.
func (p *Parser) ConvertVerifiableCredential(onchainCredential *Credential) (*verifiable.W3CCredential, error) {
	timestampExp, err := strconv.ParseInt(onchainCredential.Expiration, 10, 64)
	if err != nil {
		return nil,
			fmt.Errorf("failed to parse Expiration '%s': %v", onchainCredential.Expiration, err)
	}
	timestampIssuance, err := strconv.ParseInt(onchainCredential.IssuanceDate, 10, 64)
	if err != nil {
		return nil,
			fmt.Errorf("failed to parse IssuanceDate '%s': %v", onchainCredential.IssuanceDate, err)
	}
	expirationTime := time.Unix(timestampExp, 0).UTC()
	issuanceTime := time.Unix(timestampIssuance, 0).UTC()

	// build issuer DID
	issuerBI, ok := big.NewInt(0).SetString(onchainCredential.Issuer, 10)
	if !ok {
		return nil,
			fmt.Errorf("failed to convert issuer '%s' to BigInt: %v", onchainCredential.Issuer, err)
	}
	issuerDID, err := bigIntToDID(issuerBI)
	if err != nil {
		return nil,
			fmt.Errorf("failed to extract issuer DID: %v", err)
	}

	credentialStatus, err := p.convertCredentialStatus(
		issuerDID,
		onchainCredential.CredentialStatus,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to convert CredentialStatus: %v", err)
	}

	credentialSubject, err := p.convertCredentialSubject(
		onchainCredential.Context,
		onchainCredential.CredentialSubject,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to convert CredentialSubject: %v", err)
	}

	mtpProof, err := p.convertMtpProof(issuerDID, onchainCredential.Proof[0])
	if err != nil {
		return nil, fmt.Errorf("failed to convert MTPProof: %v", err)
	}

	return &verifiable.W3CCredential{
		ID:      p.convertCredentialID(onchainCredential.ID),
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

func (p *Parser) convertCredentialID(id string) string {
	if p.regenerateID {
		return fmt.Sprintf("urn:uuid:%s", uuid.New().String())
	}
	return id
}

func (p *Parser) convertCredentialStatus(
	issuerDID *w3c.DID,
	credentialStatus CredentialStatus,
) (*verifiable.CredentialStatus, error) {
	switch verifiable.CredentialStatusType(credentialStatus.Type) {
	case verifiable.Iden3OnchainSparseMerkleTreeProof2023:
		nonce, err := strconv.ParseUint(credentialStatus.RevocationNonce, 10, 64)
		if err != nil {
			return nil,
				fmt.Errorf("invalid revocationNonce '%s': %v", credentialStatus.RevocationNonce, err)
		}

		chainID, err := core.ChainIDfromDID(*issuerDID)
		if err != nil {
			return nil,
				fmt.Errorf("failed to extract chainID from DID: %v", err)
		}
		issuerID, err := core.IDFromDID(*issuerDID)
		if err != nil {
			return nil,
				fmt.Errorf("failed to extract ID from DID: %v", err)
		}
		contractAddress, err := core.EthAddressFromID(issuerID)
		if err != nil {
			return nil,
				fmt.Errorf("failed to extract contract address from ID: %v", err)
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

func (p *Parser) convertCredentialSubject(
	credentialContext []string,
	fields []CredentialSubjectField,
) (map[string]any, error) {
	var (
		idIsSet   bool
		typeIsSet bool

		credentialSubject = make(map[string]any)
	)

	contextbytes, err := json.Marshal(map[string][]string{
		"@context": credentialContext,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal context: %v", err)
	}

	// process required fields in credential subject
	for _, f := range fields {
		switch f.Key {
		case "id":
			idIsSet = true
			ownderID, ok := big.NewInt(0).SetString(f.Value, 10)
			if !ok {
				return nil,
					fmt.Errorf("failed to extract ownerID '%s' from CredentialSubject", f.Value)
			}
			ownerDID, err := bigIntToDID(ownderID)
			if err != nil {
				return nil,
					fmt.Errorf("failed to convert ownerID '%s' to DID: %v", f.Value, err)
			}
			credentialSubject["id"] = ownerDID.String()
		case "type":
			typeIsSet = true
			hexBytes, err := hex.DecodeString(hexWithoutPrefix(f.RawValue))
			if err != nil {
				return nil,
					fmt.Errorf("failed to decode hex '%s' from CredentialSubject: %v", f.RawValue, err)
			}
			credentialSubject["type"] = string(hexBytes)
		}
	}

	if !idIsSet || !typeIsSet {
		return nil, fmt.Errorf("CredentialSubject does not have required fields: id, type")
	}

	for _, f := range fields {
		// skip already processed fields
		if f.Key == "id" || f.Key == "type" {
			continue
		}

		datatype, err := p.marklizeInstance.TypeFromContext(
			contextbytes,
			fmt.Sprintf("%s.%s", credentialSubject["type"], f.Key),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to extract type for field '%s': %v", f.Key, err)
		}

		switch datatype {
		case ld.XSDBoolean:
			switch f.Value {
			case BooleanHashTrue:
				credentialSubject[f.Key] = true
			case BooleanHashFalse:
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
			bi, ok := new(big.Int).SetString(f.Value, 10)
			if !ok {
				return nil,
					fmt.Errorf("failed to convert string '%s' to BigInt", f.Value)
			}
			credentialSubject[f.Key] = bi.Int64()
		case ld.XSDString:
			strBytes, err := hex.DecodeString(hexWithoutPrefix(f.RawValue))
			if err != nil {
				return nil,
					fmt.Errorf("failed to decode hex '%s' from CredentialSubject: %v", f.RawValue, err)
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

	return credentialSubject, nil
}

func (p *Parser) convertMtpProof(
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
		return nil, fmt.Errorf("failed to create core claim: %v", err)
	}

	mtp, err := convertChainProofToMerkleProof(&smtproof{
		existence:    issuanceProof.MTP.Existence,
		siblings:     issuanceProof.MTP.Siblings,
		auxExistence: issuanceProof.MTP.AuxExistence,
		auxIndex:     issuanceProof.MTP.AuxIndex,
		auxValue:     issuanceProof.MTP.AuxValue,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to convert chain proof to merkle proof: %v", err)
	}

	coreClaimHex, err := coreClaim.Hex()
	if err != nil {
		return nil, fmt.Errorf("failed to convert CoreClaim to hex: %v", err)
	}

	rootOfRoots, err := merkletree.NewHashFromString(issuanceProof.IssuerData.State.RootOfRoots)
	if err != nil {
		return nil,
			fmt.Errorf("failed to convert RootOfRoots '%s' to hash: %v", issuanceProof.IssuerData.State.RootOfRoots, err)
	}
	claimsTreeRoot, err := merkletree.NewHashFromString(issuanceProof.IssuerData.State.ClaimsTreeRoot)
	if err != nil {
		return nil,
			fmt.Errorf("failed to convert ClaimsTreeRoot '%s' to hash: %v", issuanceProof.IssuerData.State.ClaimsTreeRoot, err)
	}
	revocationTreeRoot, err := merkletree.NewHashFromString(issuanceProof.IssuerData.State.RevocationTreeRoot)
	if err != nil {
		return nil,
			fmt.Errorf("failed to convert RevocationTreeRoot '%s' to hash: %v", issuanceProof.IssuerData.State.RevocationTreeRoot, err)
	}
	value, err := merkletree.NewHashFromString(issuanceProof.IssuerData.State.Value)
	if err != nil {
		return nil,
			fmt.Errorf("failed to convert Value '%s' to hash: %v", issuanceProof.IssuerData.State.Value, err)
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
			fmt.Errorf("failed to convert BigInt '%s' to ID: %v", bi.String(), err)
	}
	did, err := core.ParseDIDFromID(id)
	if err != nil {
		return nil,
			fmt.Errorf("failed to convert ID to DID: %v", err)
	}
	return did, nil
}

func strPtr(s string) *string {
	return &s
}

func validateSourceValue(datatype, origin string, source any) error {
	sourceHash, err := merklize.HashValue(datatype, source)
	if err != nil {
		return fmt.Errorf("failed hash value '%s' with data type '%s': %v", source, datatype, err)
	}
	origineHash, ok := big.NewInt(0).SetString(origin, 10)
	if !ok {
		return fmt.Errorf("invalid origin '%s'", origin)
	}
	if sourceHash.Cmp(origineHash) != 0 {
		return fmt.Errorf("hash of value '%s' does not match core claim value '%s'", sourceHash, origineHash)
	}
	return nil
}

type smtproof struct {
	existence    bool
	auxExistence bool
	auxIndex     string
	auxValue     string
	siblings     []string
}

func convertChainProofToMerkleProof(smtProof *smtproof) (*merkletree.Proof, error) {
	var (
		existence bool
		nodeAux   *merkletree.NodeAux
		err       error
	)

	if smtProof.existence {
		existence = true
	} else {
		existence = false
		if smtProof.auxExistence {
			nodeAux = &merkletree.NodeAux{}
			nodeAux.Key, err = merkletree.NewHashFromString(smtProof.auxIndex)
			if err != nil {
				return nil, err
			}
			nodeAux.Value, err = merkletree.NewHashFromString(smtProof.auxValue)
			if err != nil {
				return nil, err
			}
		}
	}

	allSiblings := make([]*merkletree.Hash, len(smtProof.siblings))
	for i, s := range smtProof.siblings {
		sh, err := merkletree.NewHashFromString(s)
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
