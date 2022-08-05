package saml

import (
	"bytes"
	"context"

	"github.com/crewjam/saml/samlsp"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/x/jsonx"
	"github.com/pkg/errors"
)

type ProviderSAML struct {
	id     string
	label  string
	config *Configuration
}

func NewProviderSAML(
	id string,
	label string,
	config *Configuration,
) *ProviderSAML {
	return &ProviderSAML{
		id:     id,
		label:  label,
		config: config,
	}
}

// Translate attributes from saml asseryion into kratos claims
func (d *ProviderSAML) Claims(ctx context.Context, config *config.Config, attributeSAML samlsp.Attributes) (*Claims, error) {

	var c ConfigurationCollection

	conf := config.SelfServiceStrategy("saml").Config
	if err := jsonx.
		NewStrictDecoder(bytes.NewBuffer(conf)).
		Decode(&c); err != nil {
		return nil, errors.Wrapf(err, "Unable to decode config %v", string(conf))
	}

	providerSAML := c.SAMLProviders[len(c.SAMLProviders)-1]

	claims := &Claims{
		Issuer:        "saml",
		Subject:       attributeSAML.Get(providerSAML.AttributesMap["id"]),
		Name:          attributeSAML.Get(providerSAML.AttributesMap["firstname"]),
		LastName:      attributeSAML.Get(providerSAML.AttributesMap["lastname"]),
		Nickname:      attributeSAML.Get(providerSAML.AttributesMap["nickname"]),
		Gender:        attributeSAML.Get(providerSAML.AttributesMap["gender"]),
		Birthdate:     attributeSAML.Get(providerSAML.AttributesMap["birthdate"]),
		Picture:       attributeSAML.Get(providerSAML.AttributesMap["picture"]),
		Email:         attributeSAML.Get(providerSAML.AttributesMap["email"]),
		Roles:         attributeSAML[providerSAML.AttributesMap["roles"]],
		Groups:        attributeSAML[providerSAML.AttributesMap["groups"]],
		PhoneNumber:   attributeSAML.Get(providerSAML.AttributesMap["phone_number"]),
		EmailVerified: true,
	}

	return claims, nil
}

func (d *ProviderSAML) Config() *Configuration {
	return d.config
}
