package saml

type Configuration struct {
	// ID is the provider's ID
	ID string `json:"id"`

	// Label represents an optional label which can be used in the UI generation.
	Label string `json:"label"`

	// Represent the path of the certificate of your application
	PublicCertPath string `json:"public_cert_path"`

	// Represent the path of the private key of your application
	PrivateKeyPath string `json:"private_key_path"`

	// It is a map where you have to name the attributes contained in the SAML response to associate them with their value
	AttributesMap map[string]string `json:"attributes_map"`

	// Information about the IDP like the sso url, slo url, entiy ID, metadata url
	IDPInformation map[string]string `json:"idp_information"`

	// Mapper specifies the JSONNet code snippet
	// It can be either a URL (file://, http(s)://, base64://) or an inline JSONNet code snippet.
	Mapper string `json:"mapper_url"`
}

type ConfigurationCollection struct {
	SAMLProviders []Configuration `json:"providers"`
}

func (c ConfigurationCollection) Provider(id string, label string) (Provider, error) {
	return NewProviderSAML(id, label, &c.SAMLProviders[len(c.SAMLProviders)-1]), nil

}
