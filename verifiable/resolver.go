package verifiable

import (
	"context"
	"fmt"

	"github.com/iden3/go-iden3-core/v2/w3c"
)

// CredentialStatusResolveOptions options for CredentialStatusResolver Resolve
type CredentialStatusResolveOptions struct {
	UserDID   *w3c.DID
	IssuerDID *w3c.DID
}

// CredentialStatusResolver is an interface that allows to interact with deifferent types of credential status to resolve revocation status
type CredentialStatusResolver interface {
	Resolve(ctx context.Context, credentialStatus CredentialStatus, opts *CredentialStatusResolveOptions) (RevocationStatus, error)
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
