package app

import (
	"context"
	"errors"

	"github.com/karalef/quark"
	"github.com/karalef/quark-cmd/config"
	"github.com/karalef/quark-cmd/storage"
	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/kem"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/encrypted/key"
	"github.com/karalef/quark/extensions/subkey"
)

type appCtxKey struct{}

func Context(ctx context.Context, a *App) context.Context {
	return context.WithValue(ctx, appCtxKey{}, a)
}

func FromContext(ctx context.Context) *App {
	return ctx.Value(appCtxKey{}).(*App)
}

func New(pubring storage.Pubring, secrets storage.Secrets, cfg config.Config) *App {
	return &App{pubring: pubring, secrets: secrets, cfg: cfg}
}

type App struct {
	pubring storage.Pubring
	secrets storage.Secrets
	cfg     config.Config
}

type PassphraseFunc = func() (string, error)

func (a *App) loadSK(id crypto.ID, pf PassphraseFunc) (*key.Key, string, error) {
	k, err := a.secrets.ByID(id)
	if err != nil {
		return nil, "", err
	}

	pass, err := pf()
	return k, pass, err
}

func (a *App) LoadSignSecret(id crypto.ID, pf PassphraseFunc) (sign.PrivateKey, error) {
	k, pass, err := a.loadSK(id, pf)
	if err != nil {
		return nil, err
	}
	sk, err := k.DecryptSign(pass)
	return sk, err
}

func (a *App) LoadKEMSecret(id crypto.ID, pf PassphraseFunc) (kem.PrivateKey, error) {
	k, pass, err := a.loadSK(id, pf)
	if err != nil {
		return nil, err
	}
	sk, err := k.DecryptKEM(pass)
	return sk, err
}

type deleteConfirm = func(withSecret bool) (bool, error)

func (a *App) Delete(ider IDer, confirm deleteConfirm) error {
	id, err := ider.ID()
	if err != nil {
		return err
	}
	exist, err := a.pubring.IsExists(id)
	if err != nil {
		return err
	}
	if !exist {
		return storage.ErrNotFound
	}
	skExist, err := a.secrets.IsExists(id)
	if err != nil {
		return err
	}

	if confirm != nil {
		var ok bool
		ok, err = confirm(skExist)
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
	}

	var key *Key
	if !skExist {
		goto deletePub
	}
	key, err = a.Load(ider)
	if err != nil {
		return err
	}
	key.VisitSubkeys(func(sub quark.Certificate[subkey.Subkey]) bool {
		err = a.secrets.Delete(sub.Data.ID())
		if err == storage.ErrNotFound {
			err = nil
		}
		return err != nil
	})
	err = a.secrets.Delete(id)
	if err != nil {
		return err
	}

deletePub:
	return a.pubring.Delete(id)
}

func (a *App) Import(k *quark.Key, secrets ...*key.Key) error {
	if k == nil {
		return nil
	}
	err := a.pubring.Store(k)
	if err != nil {
		return err
	}
	for _, sk := range secrets {
		err = a.secrets.Store(sk)
		if err != nil {
			return err
		}
	}
	return nil
}

// IDer represents an ID.
type IDer interface {
	ID() (crypto.ID, error)
	IsFP() bool
	FP() (crypto.Fingerprint, error)
}

var (
	_ IDer = ID{}
	_ IDer = IDStr("")
	_ IDer = FP{}
	_ IDer = FPStr("")
)

// IDer implementation.
type (
	ID    crypto.ID
	IDStr string
	FP    crypto.Fingerprint
	FPStr string
)

func (id ID) ID() (crypto.ID, error)     { return crypto.ID(id), nil }
func (str IDStr) ID() (crypto.ID, error) { return ParseID(string(str)) }
func (fp FP) ID() (crypto.ID, error) {
	f, err := fp.FP()
	if err != nil {
		return crypto.ID{}, err
	}
	return f.ID(), nil
}

func (str FPStr) ID() (crypto.ID, error) {
	f, err := str.FP()
	if err != nil {
		return crypto.ID{}, err
	}
	return f.ID(), nil
}

func (id ID) IsFP() bool     { return false }
func (str IDStr) IsFP() bool { return false }
func (fp FP) IsFP() bool     { return true }
func (str FPStr) IsFP() bool { return true }

func (id ID) FP() (crypto.Fingerprint, error)     { return crypto.Fingerprint{}, nil }
func (str IDStr) FP() (crypto.Fingerprint, error) { return crypto.Fingerprint{}, nil }
func (fp FP) FP() (crypto.Fingerprint, error)     { return crypto.Fingerprint(fp), nil }
func (str FPStr) FP() (crypto.Fingerprint, error) { return ParseFP(string(str)) }

// ParseID returns ID from string.
func ParseID(s string) (crypto.ID, error) {
	id, ok := crypto.IDFromString(s)
	if !ok {
		return crypto.ID{}, errInvalidID
	}
	return id, nil
}

// ParseFP returns Fingerprint from string.
func ParseFP(s string) (crypto.Fingerprint, error) {
	fp, ok := crypto.ParseFingerprint(s)
	if !ok {
		return crypto.Fingerprint{}, errInvalidFP
	}
	return fp, nil
}

var (
	errInvalidID = errors.New("invalid ID")
	errInvalidFP = errors.New("invalid Fingerprint")
)

// ErrIDColission is returned when there is more than one object with the same ID.
var ErrIDColission = errors.New("there is more than one object with the same ID")
