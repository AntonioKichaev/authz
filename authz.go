// Copyright 2014 Manu Martinez-Almeida.  All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package authz

import (
	"net/http"

	"github.com/casbin/casbin/v2"
	"github.com/gin-gonic/gin"
)

type AuthorizerOption func(*AuthorizerParams)

func WithAuthorizer(a Authorizer) AuthorizerOption {
	return func(p *AuthorizerParams) {
		p.authorizer = a
	}
}

type Authorizer interface {
	CheckPermission(c *http.Request) bool
	RequirePermission(c *gin.Context)
}

type AuthorizerParams struct {
	authorizer Authorizer
}

// NewAuthorizer returns the authorizer, uses a Casbin enforcer as input
func NewAuthorizer(e *casbin.Enforcer, options ...AuthorizerOption) gin.HandlerFunc {
	a := &BasicAuthorizer{enforcer: e}

	params := &AuthorizerParams{
		//As a default authorizer we use BasicAuthorizer
		authorizer: a,
	}

	for _, option := range options {
		option(params)
	}

	return func(c *gin.Context) {
		if !params.authorizer.CheckPermission(c.Request) {
			params.authorizer.RequirePermission(c)
		}
	}
}

// BasicAuthorizer stores the casbin handler
type BasicAuthorizer struct {
	enforcer *casbin.Enforcer
}

// GetUserName gets the user name from the request.
// Currently, only HTTP basic authentication is supported
func (a *BasicAuthorizer) GetUserName(r *http.Request) string {
	username, _, _ := r.BasicAuth()
	return username
}

// CheckPermission checks the user/method/path combination from the request.
// Returns true (permission granted) or false (permission forbidden)
func (a *BasicAuthorizer) CheckPermission(r *http.Request) bool {
	user := a.GetUserName(r)
	method := r.Method
	path := r.URL.Path

	allowed, err := a.enforcer.Enforce(user, path, method)
	if err != nil {
		panic(err)
	}

	return allowed
}

// RequirePermission returns the 403 Forbidden to the client
func (a *BasicAuthorizer) RequirePermission(c *gin.Context) {
	c.AbortWithStatus(http.StatusForbidden)
}
