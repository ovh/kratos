package saml

import (
	"github.com/ory/kratos/text"
	"github.com/ory/kratos/ui/node"
)

func NewLinkNode() *node.Node {
	return node.NewInputField("samlLink", "saml", node.SAMLGroup, node.InputAttributeTypeSubmit).WithMetaLabel(text.NewInfoSelfServiceSettingsUpdateLinkSAML())
}

func NewUnlinkNode(provider string) *node.Node {
	return node.NewInputField("samlUnlink", provider, node.SAMLGroup, node.InputAttributeTypeSubmit).WithMetaLabel(text.NewInfoSelfServiceSettingsUpdateUnlinkSAML(provider))
}
