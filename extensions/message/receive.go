package message

import (
	"errors"
	"io"

	"github.com/karalef/quark"
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/kem"
	"github.com/karalef/quark/crypto/mac"
	"github.com/karalef/quark/internal"
	"github.com/karalef/quark/pack"
)

type messageReader struct {
	io.Reader
}

// Decrypt contains the parameters to decrypt the message.
type Decrypt struct {
	// Issuer is used to verify the signature.
	Issuer quark.PublicKey

	// Recipient is used to decrypt the message.
	Recipient kem.PrivateKey
	// Password is used to decrypt the message.
	Password string
}

func (msg *Message) Decrypt(plain io.Writer, decrypt Decrypt) error {
	// Verify signature
	verifier := internal.NopCloser(plain)
	if !msg.Header.Sender.IsEmpty() && decrypt.Issuer != nil {
		verifier = messageVerifier{
			w:   plain,
			msg: msg,
			v:   quark.VerifyStream(decrypt.Issuer),
		}
	}
	msg.Data.Writer = verifier

	// Decrypt
	mr := &messageReader{}
	var md messageDecrypter
	msgReader := io.Reader(mr)
	if enc := msg.Header.Encryption; enc != nil {
		var cipher aead.Cipher
		var err error
		if enc.IsEncapsulated() {
			if decrypt.Recipient == nil {
				return errors.New("message is public key encrypted but no recipient's private key provided")
			}
			cipher, err = enc.Decapsulate(decrypt.Recipient, nil)
		} else if decrypt.Password != "" {
			cipher, err = enc.Decrypt(decrypt.Password, nil)
		} else {
			err = errors.New("message is encrypted with password but no password provided")
		}
		if err != nil {
			return err
		}
		md = messageDecrypter{
			msg: msg,
			Reader: aead.Reader{
				AEAD: cipher,
				R:    msgReader,
			},
		}
		msgReader = md
	}

	// Decompress
	if comp := msg.Header.Compression; comp != nil {
		dec, err := comp.Decompress(msgReader, nil)
		if err != nil {
			return err
		}
		msgReader = dec
	}

	msg.Data.WrapReader(func(r io.Reader) io.Reader {
		mr.Reader = r
		return msgReader
	})

	dec := pack.GetDecoder(msg.Data.Reader)
	defer pack.PutDecoder(dec)

	err := dec.Decode(&msg.Data)
	if err != nil {
		return err
	}
	err = dec.Decode(&msg.Auth)
	if err != nil {
		return err
	}

	return errors.Join(verifier.Close(), md.Close())
}

type messageDecrypter struct {
	msg *Message
	aead.Reader
}

func (d messageDecrypter) Close() error {
	if d.msg == nil {
		return nil
	}
	if !mac.Equal(d.msg.Auth.Tag, d.AEAD.Tag(nil)) {
		return mac.ErrMismatch
	}
	return nil
}

type messageVerifier struct {
	w   io.Writer
	msg *Message
	v   *quark.Verifier
}

func (v messageVerifier) Write(p []byte) (n int, err error) {
	n, err = v.w.Write(p)
	if n != 0 {
		_, verr := v.v.Write(p[:n])
		if err == nil {
			err = verr
		}
	}
	return
}

func (v messageVerifier) Close() error {
	ok, err := v.v.Verify(v.msg.Auth.Signature)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("the signature cannot be verified, it may have been forged")
	}
	return nil
}
