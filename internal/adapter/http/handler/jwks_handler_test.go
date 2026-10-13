package handler

import (
	"errors"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
	"github.com/andrewhigh08/iam-service/test/mocks"
)

func jwksRouter(t *testing.T) (*gin.Engine, *mocks.MockAuthService) {
	t.Helper()
	auth := mocks.NewMockAuthService(gomock.NewController(t))
	r := gin.New()
	r.GET("/.well-known/jwks.json", NewJWKSHandler(auth).JWKS)
	return r, auth
}

func TestJWKS_ServesTheKeySetVerbatim(t *testing.T) {
	t.Parallel()
	r, auth := jwksRouter(t)
	keySet := `{"keys":[{"kty":"RSA","kid":"k1","alg":"RS256","use":"sig","n":"abc","e":"AQAB"}]}`
	auth.EXPECT().PublicJWKS().Return([]byte(keySet), nil)

	rec := serve(r, newRequest(t, http.MethodGet, "/.well-known/jwks.json", nil))

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.JSONEq(t, keySet, rec.Body.String(), "the key set is not wrapped in the envelope")
}

func TestJWKS_MapsServiceErrors(t *testing.T) {
	t.Parallel()
	r, auth := jwksRouter(t)
	auth.EXPECT().PublicJWKS().Return(nil, apperror.Internal("failed to encode public key", errors.New("bad modulus")))

	rec := serve(r, newRequest(t, http.MethodGet, "/.well-known/jwks.json", nil))

	assertError(t, rec, http.StatusInternalServerError, apperror.CodeInternal, "failed to encode public key")
	assert.NotContains(t, rec.Body.String(), "bad modulus")
}
