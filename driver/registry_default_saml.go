package driver

import "github.com/ory/kratos/selfservice/flow/saml"

func (m *RegistryDefault) SAMLHandler() *saml.Handler {
	if m.selfserviceSAMLHandler == nil {
		m.selfserviceSAMLHandler = saml.NewHandler(m)
	}

	return m.selfserviceSAMLHandler
}
