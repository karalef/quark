package message

import (
	"io"
	"time"

	"github.com/karalef/quark"
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/extensions/message/compress"
	"github.com/karalef/quark/pack"
)

// Opt is a message option.
type Opt func(*messageOpts)

// WithEncryption sets the encryption type.
func WithEncryption(enc Encrypter) Opt {
	return func(o *messageOpts) { o.enc = enc }
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
	return func(o *messageOpts) { o.file = fi }
}

type messageOpts struct {
	sender sign.PrivateKey
	expiry int64

	enc Encrypter

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
	if messageOpts.enc != nil {
		cipher, enc, err := messageOpts.enc.Encrypt(nil)
		if err != nil {
			return nil, err
		}
		msg.Header.Encryption = enc
		msgWriter = newEncrypter(msgWriter, msg, cipher)
	}

	if comp := messageOpts.compression; comp != nil {
		msg.Header.Compression = &compress.Algorithm{Compression: comp}
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
	msg.Header.Sender = sender.Fingerprint()
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

func newEncrypter(writer io.WriteCloser, msg *Message, cipher aead.Cipher) io.WriteCloser {
	return ChainCloser(writer, messageEncrypter{
		msg: msg,
		Writer: aead.Writer{
			AEAD: cipher,
			W:    writer,
		},
	})
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
