package secretsharing

import (
	"github.com/cloudflare/circl/group"
	"github.com/karalef/quark/scheme"
)

func init() {
	Schemes.Register(Risretto255)
	Schemes.Register(P256)
	Schemes.Register(P384)
	Schemes.Register(P521)
}

// groups.
var (
	Risretto255 = New("ristretto255", group.Ristretto255)
	P256        = New("P-256", group.P256)
	P384        = New("P-384", group.P384)
	P521        = New("P-521", group.P521)
)

// New creates a new scheme with specified group.
// It does not register the scheme.
func New(name string, g group.Group) Scheme {
	return sharingScheme{
		String: scheme.String(name),
		g:      g,
	}
}

// Schemes is a registry of secret sharing schemes.
var Schemes = make(scheme.Map[Scheme])

// Registry implements scheme.ByName.
type Registry struct{}

var _ scheme.ByName[Scheme] = Registry{}

func (Registry) ByName(name string) (Scheme, error) { return Schemes.ByName(name) }
