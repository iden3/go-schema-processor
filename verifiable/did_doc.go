package verifiable

import (
	"encoding/json"
	liberr "errors"
	"fmt"

	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/pkg/errors"
)

var (
	ErrVerificationMethodNotFound = liberr.New("verification method not found")
)

// DIDDocument defines current supported did doc model.
type DIDDocument struct {
	Context            interface{}                `json:"@context"`
	ID                 string                     `json:"id"`
	Service            []interface{}              `json:"service,omitempty"`
	VerificationMethod []CommonVerificationMethod `json:"verificationMethod,omitempty"`
	AssertionMethod    []Authentication           `json:"assertionMethod,omitempty"`
	Authentication     []Authentication           `json:"authentication,omitempty"`
	KeyAgreement       []Authentication           `json:"keyAgreement,omitempty"`
}

func (d *DIDDocument) ResolveVerificationMethods() CommonVerificationMethods {
	return CommonVerificationMethods(d.VerificationMethod)
}

func (d *DIDDocument) resolveToVM(items []Authentication) (CommonVerificationMethods, error) {
	vms := make(CommonVerificationMethods, 0, len(items))
	for _, auth := range d.Authentication {
		if auth.IsDID() {
			vm, err := d.ResolveVerificationMethods().FilterBy(WithID(auth.DID()))
			if err != nil {
				return nil, err
			}
			if len(vm) != 1 {
				return nil,
					fmt.Errorf("found %d verification methods for did: %s", len(vm), auth.DID())
			}
			vms = append(vms, vm[0])
			continue
		}
		vms = append(vms, auth.CommonVerificationMethod)
	}
	return vms, nil
}

func (d *DIDDocument) ResolveAssertionVerificationMethods() (CommonVerificationMethods, error) {
	return d.resolveToVM(d.AssertionMethod)
}

func (d *DIDDocument) ResolveAuthVerificationMethods() (CommonVerificationMethods, error) {
	return d.resolveToVM(d.Authentication)
}

func (d *DIDDocument) ResolveKeyAgreementVerificationMethods() (CommonVerificationMethods, error) {
	return d.resolveToVM(d.KeyAgreement)
}

// Service describes standard DID document service field.
type Service struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	ServiceEndpoint string `json:"serviceEndpoint"`
}

// WebRedirectService describes the service of web redirection
type WebRedirectService struct {
	Service
	Method string `json:"method"`
}

// PushService describes the services of push notifications
type PushService struct {
	Service
	Metadata PushMetadata `json:"metadata"`
}

// PushMetadata describes the structure of the data for push notifications
type PushMetadata struct {
	Devices []EncryptedDeviceMetadata `json:"devices"`
}

// EncryptedDeviceMetadata describes the structure of encrypted device metadata
type EncryptedDeviceMetadata struct {
	Ciphertext string `json:"ciphertext"` // base64 encoded
	Alg        string `json:"alg"`
}

// DeviceMetadata describes the structure of device metadata
type DeviceMetadata struct {
	AppID     string `json:"app_id"`
	PushToken string `json:"push_token"`
}

type CommonVerificationMethods []CommonVerificationMethod

// CommonVerificationMethod DID doc verification method.
type CommonVerificationMethod struct {
	ID                   string                 `json:"id"`
	Type                 string                 `json:"type"`
	Controller           string                 `json:"controller"`
	PublicKeyJwk         map[string]interface{} `json:"publicKeyJwk,omitempty"`
	PublicKeyMultibase   string                 `json:"publicKeyMultibase,omitempty"`
	PublicKeyHex         string                 `json:"publicKeyHex,omitempty"`
	PublicKeyBase58      string                 `json:"publicKeyBase58,omitempty"`
	EthereumAddress      string                 `json:"ethereumAddress,omitempty"`
	BlockchainAccountID  string                 `json:"blockchainAccountId,omitempty"`
	StateContractAddress string                 `json:"stateContractAddress,omitempty"`
	IdentityState
}

// TODO (illia-korotia): resolve key depend on cvm.Type
// pseudocode:
// if EcdsaSecp256k1VerificationKey2019 = resilve from PublicKeyJwk or PublicKeyMultibase or ...
// if EddsaBJJVerificationKey = resolve only from PublicKeyJwk
// etc...
// func (cvm *CommonVerificationMethod) Key() (*crypto.PublicKey)

type Authentication struct {
	CommonVerificationMethod
	did string
}

func (a *Authentication) IsDID() bool {
	return a.did != ""
}

func (a *Authentication) DID() string {
	return a.did
}

func (a *Authentication) UnmarshalJSON(b []byte) error {
	if b == nil {
		return nil
	}
	type Alias Authentication
	switch b[0] {
	case '{':
		tmp := Alias{}
		err := json.Unmarshal(b, &tmp)
		if err != nil {
			return errors.Errorf("invalid json payload for authentication: %v", err)
		}
		*a = Authentication(tmp)
	case '"':
		err := json.Unmarshal(b, &a.did)
		if err != nil {
			return fmt.Errorf("faild parse did: %v", err)
		}
	default:
		return errors.New("authentication is invalid")
	}
	return nil
}

func (a *Authentication) MarshalJSON() ([]byte, error) {
	if a.did == "" {
		return json.Marshal(a.CommonVerificationMethod)
	} else {
		return json.Marshal(a.did)
	}
}

// StateInfo is information about identity state
type StateInfo struct {
	ID                  string `json:"id"`
	State               string `json:"state"`
	ReplacedByState     string `json:"replacedByState"`
	CreatedAtTimestamp  string `json:"createdAtTimestamp"`
	ReplacedAtTimestamp string `json:"replacedAtTimestamp"`
	CreatedAtBlock      string `json:"createdAtBlock"`
	ReplacedAtBlock     string `json:"replacedAtBlock"`
}

// GistInfo representation state of gist root.
type GistInfo struct {
	Root                string         `json:"root"`
	ReplacedByRoot      string         `json:"replacedByRoot"`
	CreatedAtTimestamp  string         `json:"createdAtTimestamp"`
	ReplacedAtTimestamp string         `json:"replacedAtTimestamp"`
	CreatedAtBlock      string         `json:"createdAtBlock"`
	ReplacedAtBlock     string         `json:"replacedAtBlock"`
	Proof               *GistInfoProof `json:"proof,omitempty"`
}

// GistInfoProof representation proof of GistInfo object.
type GistInfoProof struct {
	merkletree.Proof
	Type ProofType `json:"type"`
}

// MarshalJSON for GistInfoProof
func (g GistInfoProof) MarshalJSON() ([]byte, error) {
	proofData, err := json.Marshal(g.Proof)
	if err != nil {
		return nil, err
	}
	proof := map[string]interface{}{}
	if err := json.Unmarshal(proofData, &proof); err != nil {
		return nil, err
	}
	proof["type"] = g.Type
	return json.Marshal(proof)
}

// UnmarshalJSON for GistInfoProof
func (g *GistInfoProof) UnmarshalJSON(data []byte) error {
	var proof merkletree.Proof
	if err := json.Unmarshal(data, &proof); err != nil {
		return err
	}

	typeStruct := struct {
		Type ProofType `json:"type"`
	}{}
	if err := json.Unmarshal(data, &typeStruct); err != nil {
		return err
	}

	g.Proof = proof
	g.Type = typeStruct.Type
	return nil
}

// IdentityState representation all info about identity.
type IdentityState struct {
	Published *bool      `json:"published,omitempty"`
	Info      *StateInfo `json:"info,omitempty"`
	Global    *GistInfo  `json:"global,omitempty"`
}

type VerificationMethodFilter struct {
	byID           string
	byType         string
	byController   string
	byKeyType      string
	byKeyAlgorithm string
}

type VerificationMethodFilterOpt func(*VerificationMethodFilter)

func WithID(id string) VerificationMethodFilterOpt {
	return func(f *VerificationMethodFilter) {
		f.byID = id
	}
}

func WithType(typ string) VerificationMethodFilterOpt {
	return func(f *VerificationMethodFilter) {
		f.byType = typ
	}
}

func WithController(controller string) VerificationMethodFilterOpt {
	return func(f *VerificationMethodFilter) {
		f.byController = controller
	}
}

func WithKeyType(keyType string) VerificationMethodFilterOpt {
	return func(f *VerificationMethodFilter) {
		f.byKeyType = keyType
	}
}

func WithKeyAlgorithm(algorithm string) VerificationMethodFilterOpt {
	return func(f *VerificationMethodFilter) {
		f.byKeyAlgorithm = algorithm
	}
}

func (cvm CommonVerificationMethods) FilterBy(opts ...VerificationMethodFilterOpt) (CommonVerificationMethods, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("empty filter options")
	}
	var filter VerificationMethodFilter
	for _, opt := range opts {
		opt(&filter)
	}

	filtered := CommonVerificationMethods{}
	for _, vm := range cvm {
		if filter.byID != "" && vm.ID != filter.byID {
			continue
		}
		if filter.byType != "" && vm.Type != filter.byType {
			continue
		}
		if filter.byController != "" && vm.Controller != filter.byController {
			continue
		}
		if filter.byKeyType != "" && vm.PublicKeyJwk["kty"] != filter.byKeyType {
			continue
		}
		if filter.byKeyAlgorithm != "" && vm.PublicKeyJwk["alg"] != filter.byKeyAlgorithm {
			continue
		}
		filtered = append(filtered, vm)
	}
	if filter.byID != "" && len(filtered) > 1 {
		return filtered[:1], nil
	}
	return filtered, nil
}
