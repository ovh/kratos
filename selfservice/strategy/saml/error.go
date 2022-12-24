package saml

import (
	"github.com/ory/jsonschema/v3"
	"github.com/ory/kratos/schema"
	"github.com/ory/kratos/text"
	"github.com/pkg/errors"
	"net/http"

	"github.com/ory/herodot"
	"google.golang.org/grpc/codes"
)

var (
	ErrAPIFlowNotSupported = herodot.ErrBadRequest.WithError("API-based flows are not supported for this method").
				WithReason("SAML SignIn and Registeration are only supported for flows initiated using the Browser endpoint.")

	ErrInvalidSAMLMetadataError = herodot.DefaultError{
		StatusField:   http.StatusText(http.StatusOK),
		ErrorField:    "Not valid SAML metadata file",
		CodeField:     http.StatusOK,
		GRPCCodeField: codes.InvalidArgument,
	}

	ErrInvalidCertificateError = herodot.DefaultError{
		StatusField:   http.StatusText(http.StatusOK),
		ErrorField:    "Not valid certificate",
		CodeField:     http.StatusOK,
		GRPCCodeField: codes.InvalidArgument,
	}

	ErrInvalidSAMLConfiguration = herodot.DefaultError{
		StatusField:   http.StatusText(http.StatusOK),
		ErrorField:    "Invalid SAML configuration in the configuration file",
		CodeField:     http.StatusOK,
		GRPCCodeField: codes.InvalidArgument,
	}
)

func NewErrProviderIDMissingError() error {
	return errors.WithStack(&schema.ValidationError{
		ValidationError: &jsonschema.ValidationError{
			Message:     "SAML Provider is unknown or has not been configured",
			InstancePtr: "#/samlProvider",
		},
		Messages: new(text.Messages).Add(text.NewValidationErrorGeneric("SAML Provider is unknown or has not been configured")),
	})
}
