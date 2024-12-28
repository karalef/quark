package app

import (
	"errors"
	"strings"
	"time"

	"github.com/karalef/quark"
	"github.com/karalef/quark-cmd/storage"
	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/kem"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/encrypted/key"
	"github.com/karalef/quark/encrypted/password"
	"github.com/karalef/quark/extensions/subkey"
)

func (a *App) Generate(scheme sign.Scheme, exp int64, password password.Scheme, pass PassphraseFunc) (crypto.ID, error) {
	k, sk, err := quark.GenerateWithValidity(scheme, quark.NewValidity(time.Now().Unix(), exp))
	if err != nil {
		return crypto.ID{}, err
	}

	pp, err := pass()
	if err != nil {
		return crypto.ID{}, err
	}

	encrypted, err := key.Encrypt(sk, pp, crypto.Rand(password.NonceSize()), a.PassphraseParams(password).New())
	if err != nil {
		return crypto.ID{}, err
	}

	if err = a.pubring.Store(k); err != nil {
		if err == storage.ErrExists {
			return crypto.ID{}, errors.New("FATAL ERROR: random ID collision")
		}
		return crypto.ID{}, err
	}

	if err = a.secrets.Store(encrypted); err != nil {
		if err == storage.ErrExists {
			return crypto.ID{}, errors.New("FATAL ERROR: random ID collision")
		}
		return crypto.ID{}, err
	}

	return k.ID(), nil
}

func (a *App) List(f func(*Key) bool, priv bool) ([]*Key, error) {
	if f == nil {
		f = func(*Key) bool { return true }
	}
	var keys []*Key
	err := a.VisitAll(func(k *Key) (stop bool) {
		if f(k) {
			keys = append(keys, k)
		}
		return false
	}, priv)
	return keys, err
}

func (a *App) VisitAll(f func(*Key) (stop bool), priv bool) error {
	if f == nil {
		return nil
	}
	return a.pubring.VisitAll(func(k *quark.Key) (stop bool, err error) {
		if priv {
			ex, err := a.secrets.IsExists(k.ID())
			if err != nil || !ex {
				return false, err
			}
		}
		return f(NewKey(k, a)), nil
	})
}

func (a *App) Load(ider IDer) (*Key, error) {
	id, err := ider.ID()
	if err != nil {
		return nil, err
	}
	k, err := a.pubring.ByID(id)
	if err != nil {
		return nil, err
	}
	return NewKey(k, a), nil
}

func NewKey(key *quark.Key, app *App) *Key {
	return &Key{
		key: key,
		app: app,
	}
}

type Key struct {
	key *quark.Key
	app *App
}

func (k Key) Raw() *quark.Key                   { return k.key }
func (k Key) ID() crypto.ID                     { return k.key.ID() }
func (k Key) Fingerprint() crypto.Fingerprint   { return k.key.Fingerprint() }
func (k Key) Scheme() crypto.Scheme             { return k.key.Key().Scheme() }
func (k Key) Validity() (int64, quark.Validity) { return k.key.Validity() }

func (k Key) WithSecret(f func(sign.PrivateKey) error, pass PassphraseFunc) error {
	sk, err := k.app.LoadSignSecret(k.key.ID(), pass)
	if err != nil {
		return err
	}
	return f(sk)
}

func (k *Key) write() error {
	return k.app.pubring.Update(k.key)
}

func (k *Key) errOrWrite(err error) error {
	if err != nil {
		return err
	}
	return k.write()
}

func (k Key) iderToCert(ider IDer) (quark.CertID, error) {
	if ider.IsFP() {
		return ider.FP()
	}
	var certid quark.CertID
	id, err := ider.ID()
	if err != nil {
		return certid, err
	}
	var colission bool
	k.key.VisitAllBindingsUnsafe(func(cert *quark.RawCertificate) (stop bool) {
		if cert.ID.ID() != id {
			return false
		}
		if !certid.IsEmpty() {
			// id colission detected
			colission = true
			return true
		}
		certid = cert.ID
		return true
	})
	if colission {
		return certid, ErrIDColission
	}
	if certid.IsEmpty() {
		return certid, quark.ErrBindingNotFound
	}
	return certid, nil
}

func (k Key) Rebind(ider IDer, expires int64, pass PassphraseFunc) error {
	certid, err := k.iderToCert(ider)
	if err != nil {
		return err
	}
	return k.errOrWrite(k.WithSecret(func(sk sign.PrivateKey) error {
		return k.key.Rebind(certid, sk, quark.NewValidity(time.Now().Unix(), expires))
	}, pass))
}

func (k Key) Unbind(ider IDer) error {
	certid, err := k.iderToCert(ider)
	if err != nil {
		return err
	}
	_, err = k.key.DeleteBinding(certid)
	return k.errOrWrite(err)
}

func (k Key) RevokeBinding(ider IDer, reason string, pass PassphraseFunc) error {
	certid, err := k.iderToCert(ider)
	if err != nil {
		return err
	}
	return k.errOrWrite(k.WithSecret(func(sk sign.PrivateKey) error {
		return k.key.Rebind(certid, sk, quark.NewRevoked(time.Now().Unix(), reason))
	}, pass))
}

func (k Key) Revoke(reason string, pass PassphraseFunc) error {
	return k.errOrWrite(k.WithSecret(func(sk sign.PrivateKey) error {
		return k.key.SetValidity(sk, quark.NewRevoked(time.Now().Unix(), reason))
	}, pass))
}

func (k Key) ChangeExpiry(expiry int64, pass PassphraseFunc) error {
	return k.errOrWrite(k.WithSecret(func(sk sign.PrivateKey) error {
		return k.key.SetValidity(sk, quark.NewValidity(time.Now().Unix(), expiry))
	}, pass))
}

func (k Key) VisitDatabinds(f func(quark.RawCertificate) (stop bool)) {
	k.key.VisitAllBindings(func(cert quark.RawCertificate) (stop bool) {
		if strings.HasPrefix(cert.Type, subkey.TypeBindKey) || cert.Type == CertTypeIdentity {
			return false
		}
		return f(cert)
	})
}

func (k Key) VisitIdentities(f func(quark.Certificate[Identity]) (stop bool)) {
	k.key.VisitAllBindingsUnsafe(func(cert *quark.RawCertificate) (stop bool) {
		if cert.Type != CertTypeIdentity {
			return false
		}
		c, err := quark.CertificateAs[Identity](*cert)
		if err != nil {
			return false
		}
		return f(c)
	})
}

func (k Key) Identity(ider IDer) (quark.Certificate[Identity], error) {
	id, err := k.iderToCert(ider)
	if err != nil {
		return quark.Certificate[Identity]{}, err
	}
	return quark.GetBinding[Identity](k.key, id)
}

func (k Key) VisitSubkeys(f func(quark.Certificate[subkey.Subkey]) (stop bool)) {
	k.key.VisitAllBindingsUnsafe(func(cert *quark.RawCertificate) (stop bool) {
		if !strings.HasPrefix(cert.Type, subkey.TypeBindKey) {
			return false
		}
		c, err := quark.CertificateAs[subkey.Subkey](*cert)
		if err != nil {
			return false
		}
		return f(c)
	})
}

func (k Key) Subkey(ider IDer) (quark.Certificate[subkey.Subkey], error) {
	id, err := k.iderToCert(ider)
	if err != nil {
		return quark.Certificate[subkey.Subkey]{}, err
	}
	return quark.GetBinding[subkey.Subkey](k.key, id)
}

func (k Key) IsPrivateExist() (bool, error) {
	return k.app.secrets.IsExists(k.key.ID())
}

func (k *Key) BindID(id Identity, exp int64, pass PassphraseFunc) error {
	return k.errOrWrite(k.WithSecret(func(sk sign.PrivateKey) error {
		_, err := quark.Bind(k.key, sk, id, quark.NewValidity(time.Now().Unix(), exp))
		return err
	}, pass))
}

func (k *Key) bindSub(sk crypto.Key, sub subkey.Subkey, exp int64, pass PassphraseFunc) error {
	sec, pp, err := k.app.loadSK(k.key.ID(), pass)
	if err != nil {
		return err
	}
	secretKey, err := sec.DecryptSign(pp)
	if err != nil {
		return err
	}
	params := sec.Passphrase.Params()
	nonce := crypto.Rand(params.Scheme.NonceSize())
	encSK, err := key.Encrypt(sk, pp, nonce, params.New())
	if err != nil {
		return err
	}

	_, err = sub.BindTo(k.key, secretKey, quark.NewValidity(time.Now().Unix(), exp))
	if err != nil {
		return err
	}
	return k.errOrWrite(k.app.secrets.Store(encSK))
}

func (k *Key) BindSign(scheme sign.Scheme, exp int64, pass PassphraseFunc) error {
	sk, pk, err := sign.Generate(scheme, nil)
	if err != nil {
		return err
	}
	return k.bindSub(sk, subkey.NewSign(pk), exp, pass)
}

func (k *Key) BindKEM(scheme kem.Scheme, exp int64, pass PassphraseFunc) error {
	sk, pk, err := kem.Generate(scheme, nil)
	if err != nil {
		return err
	}
	return k.bindSub(sk, subkey.NewKEM(pk), exp, pass)
}
