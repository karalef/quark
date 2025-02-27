package secretsharing

import (
	"github.com/cloudflare/circl/group"
	"github.com/karalef/quark/scheme"
)

func init() {
	Register(Risretto255)
	Register(P256)
	Register(P384)
	Register(P521)
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

var schemes = make(scheme.Map[Scheme])

// Register registers a scheme.
func Register(scheme Scheme) { schemes.Register(scheme) }

// ByName returns the scheme by the provided name.
func ByName(name string) (Scheme, error) { return schemes.ByName(name) }

// ListNames returns all registered algorithms.
func ListNames() []string { return schemes.ListNames() }

// List returns all registered schemes.
func List() []Scheme { return schemes.List() }

// Registry implements scheme.ByName.
type Registry struct{}

var _ scheme.ByName[Scheme] = Registry{}

func (Registry) ByName(name string) (Scheme, error) { return ByName(name) }
