package supabase

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/kagent-dev/kagent/go/pkg/auth"
)

type SimpleSession struct {
	P auth.Principal
}

func (s *SimpleSession) Principal() auth.Principal {
	return s.P
}

type SupabaseAuthenticator struct {
	AuthClient *AuthClient
}

func (a *SupabaseAuthenticator) Authenticate(ctx context.Context, reqHeaders http.Header, query url.Values) (auth.Session, error) {
	authHeader := reqHeaders.Get("Authorization")
	if authHeader == "" {
		return nil, fmt.Errorf("Unauthorized: auth header not found")
	}

	accessToken := strings.TrimPrefix(authHeader, "Bearer ")
	if accessToken == authHeader {
		return nil, fmt.Errorf("Unauthorized: bearer token not found")
	}

	user, err := a.AuthClient.GetUser(ctx, accessToken)
	if err != nil {
		return nil, fmt.Errorf("Unauthorized: %w", err)
	}

	agentId := reqHeaders.Get("X-Agent-Name")
	return &SimpleSession{
		P: auth.Principal{
			User: auth.User{
				ID: user.ID,
			},
			Agent: auth.Agent{
				ID: agentId,
			},
		},
	}, nil
}

func (a *SupabaseAuthenticator) UpstreamAuth(r *http.Request, session auth.Session, upstreamPrincipal auth.Principal) error {
	// for unsecure, just forward user id in header
	if session == nil || session.Principal().User.ID == "" {
		return nil
	}
	r.Header.Set("X-User-Id", session.Principal().User.ID)
	return nil
}

func NewSupabaseAuthenticator(authClient *AuthClient) *SupabaseAuthenticator {
	return &SupabaseAuthenticator{
		AuthClient: authClient,
	}
}

func (p *SupabaseAuthenticator) Wrap(next http.Handler) http.Handler {
	return auth.AuthnMiddleware(p)(next)
}
