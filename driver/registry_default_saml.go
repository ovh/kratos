package driver

import "github.com/ory/kratos/selfservice/strategy/saml"

func (m *RegistryDefault) SAMLHandler() *saml.Handler {
	if m.selfserviceSAMLHandler == nil {
		m.selfserviceSAMLHandler = saml.NewHandler(m)
	}

	return m.selfserviceSAMLHandler
}

func (m *RegistryDefault) SAMLMiddlewareManager() *saml.MiddlewareManager {
	if m.selfserviceSAMLMiddlewareManager == nil {
		m.selfserviceSAMLMiddlewareManager = saml.NewMiddlewareManager(m)
	}

	return m.selfserviceSAMLMiddlewareManager
}
