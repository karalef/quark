package bind

import "github.com/karalef/quark"

// well-known bind types
const (
	TypeName     Type = "id.name"
	TypeNickname Type = "id.nickname"
	TypeEmail    Type = "id.email"
)

// Key binds a key to the identity.
func Ident(id *quark.Identity, sk *quark.PrivateKey, typ Type, md Metadata, data string, expires int64) (Binding, error) {
	return id.Bind(sk, quark.BindingData{
		Type:     typ,
		Metadata: md,
		Data:     []byte(data),
	}, expires)
}
