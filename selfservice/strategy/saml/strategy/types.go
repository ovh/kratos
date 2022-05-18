package strategy

import (
	"bytes"
	"encoding/json"

	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/selfservice/strategy/saml"
	"github.com/ory/kratos/text"
	"github.com/ory/kratos/ui/container"
	"github.com/ory/kratos/ui/node"
	"github.com/ory/kratos/x"
	"github.com/ory/x/stringsx"

	"github.com/pkg/errors"
)

type CredentialsConfig struct {
	Providers []ProviderCredentialsConfig `json:"providers"`
}

//Create an uniq identifier for user in database. Its look like "id + the id of the saml provider"
func NewCredentialsForSAML(subject string, provider string) (*identity.Credentials, error) {
	var b bytes.Buffer
	if err := json.NewEncoder(&b).Encode(CredentialsConfig{
		Providers: []ProviderCredentialsConfig{
			{
				Subject:  subject,
				Provider: provider,
			}},
	}); err != nil {
		return nil, errors.WithStack(x.PseudoPanic.
			WithDebugf("Unable to encode password options to JSON: %s", err))
	}

	return &identity.Credentials{
		Type:        identity.CredentialsTypeSAML,
		Identifiers: []string{uid(provider, subject)},
		Config:      b.Bytes(),
	}, nil
}

func AddProviders(c *container.Container, providers []saml.Configuration, message func(provider string) *text.Message) {
	for _, p := range providers {
		AddProvider(c, p.ID, message(
			stringsx.Coalesce(p.Label, p.ID)))
	}
}

func AddProvider(c *container.Container, providerID string, message *text.Message) {
	c.GetNodes().Append(
		node.NewInputField("samlProvider", providerID, node.SAMLGroup, node.InputAttributeTypeSubmit).WithMetaLabel(message),
	)
}

type ProviderCredentialsConfig struct {
	Subject  string `json:"subject"`
	Provider string `json:"samlProvider"`
}

type FlowMethod struct {
	*container.Container
}
