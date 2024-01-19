package verifiable

import (
	"context"
	"fmt"

	"github.com/iden3/go-iden3-core/v2/w3c"
)

// CredentialStatusResolveConfig credential status resolve config
type CredentialStatusResolveConfig struct {
	UserDID   *w3c.DID
	IssuerDID *w3c.DID
}

// CredentialStatusResolveOpt returns configuration options for resolve
type CredentialStatusResolveOpt func(opts *CredentialStatusResolveConfig)

// WithIssuerDID return new options
func WithIssuerDID(issuerDID *w3c.DID) CredentialStatusResolveOpt {
	return func(opts *CredentialStatusResolveConfig) {
		opts.IssuerDID = issuerDID
	}
}

// WithUserDID return new options
func WithUserDID(userDID *w3c.DID) CredentialStatusResolveOpt {
	return func(opts *CredentialStatusResolveConfig) {
		opts.UserDID = userDID
	}
}

// CredentialStatusResolver is an interface that allows to interact with deifferent types of credential status to resolve revocation status
type CredentialStatusResolver interface {
	Resolve(ctx context.Context, credentialStatus CredentialStatus, opts ...CredentialStatusResolveOpt) (RevocationStatus, error)
}

// CredentialStatusResolverRegistry is a registry of CredentialStatusResolver
type CredentialStatusResolverRegistry struct {
	resolvers map[CredentialStatusType]*CredentialStatusResolver
}

func (r *CredentialStatusResolverRegistry) Register(resolverType CredentialStatusType, resolver CredentialStatusResolver) {
	if len(r.resolvers) == 0 {
		r.resolvers = make(map[CredentialStatusType]*CredentialStatusResolver)
	}
	r.resolvers[resolverType] = &resolver
}

func (r *CredentialStatusResolverRegistry) Get(resolverType CredentialStatusType) (CredentialStatusResolver, error) {
	resolver, ok := r.resolvers[resolverType]
	if !ok {
		return nil, fmt.Errorf("credential status type %s id not registered", resolverType)
	}
	return *resolver, nil
}
