package identity

import (
	"fmt"
	"io"

	"github.com/karalef/quark"
	"github.com/karalef/quark/pack"
)

// CertTypeIdentity is an identity certificate type.
const CertTypeIdentity = quark.CertTypeKey + ".bind.id"

// PacketTagIdentity is an identity packet tag.
const PacketTagIdentity = 0x08

func init() {
	pack.RegisterPacketType(pack.NewType(
		(*Identity)(nil),
		"identity",
		"QUARK IDENTITY",
	))
}

// New creates a new identity.
func New(uid UserID) *Identity {
	cert := quark.NewCertificate(uid)
	return FromCertificate(&cert)
}

// FromRaw creates a subkey from a raw certificate.
func FromRaw(c quark.Raw) (*Identity, error) {
	cert, err := quark.As[UserID](c)
	if err != nil {
		return nil, err
	}
	return FromCertificate(&cert), nil
}

// FromCertificate creates a subkey from a certificate.
func FromCertificate(c *quark.Certificate[UserID]) *Identity { return (*Identity)(c) }

// Identity is an identity certificate.
type Identity quark.Certificate[UserID]

func (i *Identity) PacketTag() pack.Tag                     { return i.Certificate().PacketTag() }
func (i *Identity) Certificate() *quark.Certificate[UserID] { return (*quark.Certificate[UserID])(i) }
func (i Identity) UserID() UserID                           { return i.Data }

// NewUserID creates a new user identity.
func NewUserID(name, email, comment string) UserID {
	return UserID{Name: name, Email: email, Comment: comment}
}

var _ quark.CertData[UserID] = (*UserID)(nil)

// UserID is a user identity.
type UserID struct {
	Name    string `msgpack:"name"`
	Email   string `msgpack:"email"`
	Comment string `msgpack:"comment"`
}

// CertPacketTag returns certificate packet tag.
func (UserID) CertPacketTag() pack.Tag { return PacketTagIdentity }

// CertType implements quark.CertData interface.
func (UserID) CertType() string { return CertTypeIdentity }

// Copy implements quark.CertData interface.
func (i UserID) Copy() UserID { return i }

// SignEncode implements quark.Signable interface.
//
//nolint:errcheck
func (i UserID) SignEncode(w io.Writer) error {
	io.WriteString(w, i.Name)
	io.WriteString(w, i.Email)
	io.WriteString(w, i.Comment)
	return nil
}

func (i UserID) String() string {
	return fmt.Sprintf("%s <%s> (%s)", i.Name, i.Email, i.Comment)
}
