package bind

import "github.com/karalef/quark"

// well-known bind types
const (
	TypeName     Type = quark.BindTypeGroupID + ".name"
	TypeNickname Type = quark.BindTypeGroupID + ".nickname"
	TypeEmail    Type = quark.BindTypeGroupID + ".email"
)
