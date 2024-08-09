package bind

import "github.com/karalef/quark"

// well-known bind types
const (
	TypeName     Type = quark.BindTypeGroupID + ".name"
	TypeNickname Type = quark.BindTypeGroupID + ".nickname"
	TypeEmail    Type = quark.BindTypeGroupID + ".email"
)

// GroupID is the default ID group name.
const GroupID = string(quark.BindTypeGroupID)

// Key binds a key to the identity.
// If group is empty, it will be set to GroupKeys.
func Ident(id quark.Identity, sk quark.PrivateKey, typ Type, group string, data string, expires int64) (Binding, error) {
	if group == "" {
		group = GroupID
	}
	return id.Bind(sk, quark.BindingData{
		Type:  typ,
		Group: group,
		Data:  []byte(data),
	}, expires)
}
