package saml

import "github.com/ory/herodot"

var (
	ErrAPIFlowNotSupported = herodot.ErrBadRequest.WithError("API-based flows are not supported for this method").
		WithReasonf("SAML SignIn and Registeration are only supported for flows initiated using the Browser endpoint.")
)
