package authz

import (
	"fmt"
	"net/http"

	"github.com/casdoor/casdoor-go-sdk/casdoorsdk"
	"github.com/gin-gonic/gin"
)

type Enforcer interface {
	Enforce(params ...any) (bool, error)
}

type AdditionalEnforcerParams func(r *http.Request) []any

type BearerAuthorizer struct {
	enforcer               Enforcer
	additionalEnforcerFunc AdditionalEnforcerParams
}

func NewBearerAuthorizer(e Enforcer, additionalEnforcerFunc AdditionalEnforcerParams) *BearerAuthorizer {
	return &BearerAuthorizer{
		enforcer:               e,
		additionalEnforcerFunc: additionalEnforcerFunc,
	}
}

func (b *BearerAuthorizer) GetUserName(token string) (string, error) {
	claim, err := casdoorsdk.ParseJwtToken(token)
	if err != nil {
		return "", fmt.Errorf("ParseJwtToken: %v", err)
	}

	return claim.User.Name, nil
}

func (b *BearerAuthorizer) CheckPermission(r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return false
	}

	const prefix = "Bearer "
	if len(auth) < len(prefix) {
		return false
	}

	user, err := b.GetUserName(auth[len(prefix):])
	if err != nil {
		return false
	}

	params := b.enforcerParams(user, r)

	allowed, err := b.enforcer.Enforce(params...)
	if err != nil {
		panic(err)
	}

	return allowed
}
func (b *BearerAuthorizer) enforcerParams(user string, r *http.Request) []any {
	if b.additionalEnforcerFunc != nil {
		return b.additionalEnforcerFunc(r)
	}

	method := r.Method
	path := r.URL.Path

	params := []any{
		user,
		path,
		method,
	}

	return params
}

func (b *BearerAuthorizer) RequirePermission(c *gin.Context) {
	c.AbortWithStatus(http.StatusForbidden)
}
