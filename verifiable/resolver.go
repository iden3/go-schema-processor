package verifiable

import (
	"context"
	"fmt"

	"github.com/iden3/go-iden3-core/v2/w3c"
)

type ctxKeyIssuerDID struct{}
type ctxKeyUserDID struct{}

// WithIssuerDID puts the issuer DID in the context
func WithIssuerDID(ctx context.Context, issuerDID *w3c.DID) context.Context {
	return context.WithValue(ctx, ctxKeyIssuerDID{}, issuerDID)
}

// GetIssuerDID extract the issuer DID from the context.
// Or nil if nothing is found.
func GetIssuerDID(ctx context.Context) *w3c.DID {
	return getTpCtx[w3c.DID](ctx, ctxKeyIssuerDID{})
}

// WithUserDID puts the user DID in the context
func WithUserDID(ctx context.Context, userDID *w3c.DID) context.Context {
	return context.WithValue(ctx, ctxKeyUserDID{}, userDID)
}

// GetUserDID extract the user DID from the context.
// Or nil if nothing is found.
func GetUserDID(ctx context.Context) *w3c.DID {
	return getTpCtx[w3c.DID](ctx, ctxKeyUserDID{})
}

func getTpCtx[T any](ctx context.Context, key any) *T {
	v := ctx.Value(key)
	if v == nil {
		return nil
	}
	return v.(*T)
}

// CredentialStatusResolver is an interface that allows to interact with deifferent types of credential status to resolve revocation status
type CredentialStatusResolver interface {
	Resolve(ctx context.Context,
		credentialStatus CredentialStatus) (RevocationStatus, error)
}

// TODO: should we create a default Registry with global function to register new types???

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
