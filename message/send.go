package message

import (
	"io"
	"time"

	"github.com/karalef/quark"
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/cipher"
	"github.com/karalef/quark/crypto/kdf"
	"github.com/karalef/quark/crypto/mac"
	"github.com/karalef/quark/crypto/password"
	"github.com/karalef/quark/crypto/secret"
	"github.com/karalef/quark/crypto/xof"
	"github.com/karalef/quark/encaps"
	"github.com/karalef/quark/internal"
	"github.com/karalef/quark/message/compress"
	"github.com/karalef/quark/message/encryption"
	"github.com/karalef/quark/pack"
)

// Opt is a message option.
type Opt func(*messageOpts)

// WithEncryption enables encryption based on key encapsulation mechanism.
// Panics if recipient is nil.
func WithEncryption(recipient encaps.PublicKey, scheme ...secret.Scheme) Opt {
	if recipient == nil {
		panic("nil recipient")
	}
	return func(o *messageOpts) {
		o.recipient = recipient
		if len(scheme) > 0 {
			o.scheme = scheme[0]
		}
	}
}

// WithPassword sets password-based authenticated encryption scheme.
// WithEncryption always overrides WithPassword.
// Panics if password is empty.
func WithPassword(passwd string, params kdf.Params, scheme ...password.Scheme) Opt {
	if len(passwd) == 0 {
		panic("empty password")
	}
	return func(o *messageOpts) {
		o.password = passwd
		o.KDFParams = params
		if len(scheme) > 0 {
			o.passwordScheme = scheme[0]
		}
	}
}

// WithSignature enables message signature.
// Panics if sender is nil.
func WithSignature(sender quark.PrivateKey, expiry ...int64) Opt {
	if sender == nil {
		panic("nil sender")
	}
	return func(o *messageOpts) {
		o.sender = sender
		if len(expiry) > 0 {
			o.expiry = expiry[0]
		}
	}
}

// WithCompression enables message compression.
func WithCompression(compression compress.Compression, lvl uint, opts ...compress.Opts) Opt {
	return func(o *messageOpts) {
		o.compression = compression
		o.lvl = lvl
		if len(opts) > 0 {
			o.compressOpts = opts[0]
		}
	}
}

// WithFileInfo sets the file info.
func WithFileInfo(fi FileInfo) Opt {
	return func(o *messageOpts) {
		o.file = fi
	}
}

type messageOpts struct {
	sender quark.PrivateKey
	expiry int64

	recipient encaps.PublicKey
	scheme    secret.Scheme

	password       string
	passwordScheme password.Scheme
	KDFParams      kdf.Params

	compression  compress.Compression
	compressOpts compress.Opts
	lvl          uint

	file FileInfo
}

// Default schemes.
var (
	DefaultSymmetricScheme = aead.Build(cipher.AESCTR256, mac.SHA3_256)
	DefaultSecretScheme    = secret.Build(DefaultSymmetricScheme, xof.Shake256)
	DefaultPasswordScheme  = password.Build(DefaultSymmetricScheme, kdf.Argon2id)
)

// New creates a new message.
func New(plaintext io.Reader, opts ...Opt) (*Message, error) {
	if plaintext == nil {
		panic("New: nil plaintext")
	}
	messageOpts := &messageOpts{}
	for _, o := range opts {
		o(messageOpts)
	}

	msg := &Message{
		Header: Header{
			Time: time.Now().Unix(),
			File: messageOpts.file,
		},
		Data: pack.Stream{
			Reader: plaintext,
		},
	}

	if sender := messageOpts.sender; sender != nil {
		err := signMessage(sender, msg, messageOpts.expiry)
		if err != nil {
			return nil, err
		}
	}

	mw := &messageWriter{}
	var msgWriter io.WriteCloser = mw
	if recipient := messageOpts.recipient; recipient != nil {
		if messageOpts.scheme == nil {
			messageOpts.scheme = DefaultSecretScheme
		}
		cipher, enc, err := encryption.Encapsulate(messageOpts.scheme, recipient, nil)
		if err != nil {
			return nil, err
		}
		msg.Header.Encryption = enc
		msgWriter = internal.ChainCloser(msgWriter, messageEncrypter{
			msg: msg,
			Writer: aead.Writer{
				AEAD: cipher,
				W:    msgWriter,
			},
		})
	} else if messageOpts.password != "" {
		if messageOpts.passwordScheme == nil {
			messageOpts.passwordScheme = DefaultPasswordScheme
		}
		cipher, enc, err := encryption.PasswordEncrypt(messageOpts.passwordScheme, messageOpts.password, nil, messageOpts.KDFParams)
		if err != nil {
			return nil, err
		}
		msg.Header.Encryption = enc
		msgWriter = internal.ChainCloser(msgWriter, messageEncrypter{
			msg: msg,
			Writer: aead.Writer{
				AEAD: cipher,
				W:    msgWriter,
			},
		})
	}

	if comp := messageOpts.compression; comp != nil {
		msg.Header.Compression = &Compression{comp}
		compressed, err := comp.Compress(msgWriter, messageOpts.lvl, messageOpts.compressOpts)
		if err != nil {
			return nil, err
		}
		msgWriter = internal.ChainCloser(msgWriter, compressed)
	}

	msg.Data.WrapWriter(func(wc io.WriteCloser) io.WriteCloser {
		mw.WriteCloser = wc
		return msgWriter
	})

	return msg, nil
}

func signMessage(sender quark.PrivateKey, msg *Message, expiry int64) error {
	msg.Header.Sender = sender.ID()
	msg.Data.Reader = messageSigner{
		r:      msg.Data.Reader,
		msg:    msg,
		signer: quark.SignStream(sender),
		v:      quark.NewValidity(msg.Header.Time, expiry),
	}
	return nil
}

type messageWriter struct {
	io.WriteCloser
}

type messageEncrypter struct {
	msg *Message
	aead.Writer
}

func (e messageEncrypter) Close() error {
	e.msg.Auth.Tag = e.Writer.AEAD.Tag(nil)
	return nil
}

type messageSigner struct {
	r      io.Reader
	msg    *Message
	signer *quark.Signer
	v      quark.Validity
}

func (s messageSigner) Read(p []byte) (n int, err error) {
	n, err = s.r.Read(p)
	_, signErr := s.signer.Write(p[:n])
	if signErr != nil {
		return n, signErr
	}
	if err == io.EOF {
		s.msg.Auth.Signature, signErr = s.signer.Sign(s.v)
		if signErr != nil {
			return n, signErr
		}
	}
	return n, err
}
