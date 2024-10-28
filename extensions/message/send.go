package message

import (
	"io"
	"time"

	"github.com/karalef/quark"
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/kem"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/encrypted"
	"github.com/karalef/quark/encrypted/secret"
	"github.com/karalef/quark/extensions/message/compress"
	"github.com/karalef/quark/pack"
)

// Opt is a message option.
type Opt func(*messageOpts)

// WithEncryption enables encryption based on key encapsulation mechanism.
// Panics if recipient is nil.
func WithEncryption(recipient kem.PublicKey, scheme *secret.Scheme) Opt {
	if recipient == nil {
		panic("nil recipient")
	}
	if scheme == nil {
		panic("nil secret scheme")
	}
	return func(o *messageOpts) {
		o.recipient = recipient
		o.scheme = scheme
	}
}

// WithPassword sets password-based authenticated encryption scheme.
// WithEncryption always overrides WithPassword.
// Panics if password is empty.
func WithPassword(passwd string, params encrypted.PassphraseParams) Opt {
	if len(passwd) == 0 {
		panic("empty password")
	}
	return func(o *messageOpts) {
		o.password = passwd
		o.passwordParams = params
	}
}

// WithSignature enables message signature.
// Panics if sender is nil.
func WithSignature(sender sign.PrivateKey, expiry ...int64) Opt {
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
	sender sign.PrivateKey
	expiry int64

	recipient kem.PublicKey
	scheme    *secret.Scheme

	password       string
	passwordParams encrypted.PassphraseParams

	compression  compress.Compression
	compressOpts compress.Opts
	lvl          uint

	file FileInfo
}

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
	msgWriter := NopCloser(mw)
	if recipient := messageOpts.recipient; recipient != nil {
		cipher, enc, err := Encapsulate(messageOpts.scheme, recipient, nil)
		if err != nil {
			return nil, err
		}
		msg.Header.Encryption = enc
		msgWriter = ChainCloser(msgWriter, messageEncrypter{
			msg: msg,
			Writer: aead.Writer{
				AEAD: cipher,
				W:    msgWriter,
			},
		})
	} else if messageOpts.password != "" {
		cipher, enc, err := Password(messageOpts.password, nil, messageOpts.passwordParams)
		if err != nil {
			return nil, err
		}
		msg.Header.Encryption = enc
		msgWriter = ChainCloser(msgWriter, messageEncrypter{
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
		msgWriter = ChainCloser(msgWriter, compressed)
	}

	msg.Data.WrapWriter(func(w io.Writer) io.WriteCloser {
		mw.Writer = w
		return msgWriter
	})

	return msg, nil
}

func signMessage(sender sign.PrivateKey, msg *Message, expiry int64) error {
	msg.Header.Sender = sender.ID()
	msg.Data.Reader = messageSigner{
		r:      msg.Data.Reader,
		msg:    msg,
		signer: quark.Sign(sender),
		v:      quark.NewValidity(msg.Header.Time, expiry),
	}
	return nil
}

type messageWriter struct {
	io.Writer
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
