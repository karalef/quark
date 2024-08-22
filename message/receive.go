package message

import (
	"errors"
	"io"

	"github.com/karalef/quark"
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/mac"
	"github.com/karalef/quark/internal"
	"github.com/karalef/quark/keys/kem"
	"github.com/karalef/quark/pack"
)

// ErrBrokenMessage is returned when the message is broken.
type ErrBrokenMessage struct {
	Description string
}

func (err ErrBrokenMessage) Error() string {
	return "broken message: " + err.Description
}

type messageReader struct {
	io.Reader
}

// Decrypt decrypts a message.
func (msg *Message) Decrypt(plaintext io.Writer, recipient *kem.PrivateKey, sender *quark.PublicKey) error {
	closer := internal.NopCloser(plaintext)
	if !msg.Header.Sender.IsEmpty() {
		closer = internal.ChainCloser(closer, messageVerifier{
			w:   closer,
			msg: msg,
			v:   quark.VerifyStream(sender),
		})
	}

	mr := &messageReader{}
	var msgReader io.Reader = mr
	if msg.Header.Encryption != nil {
		cipher, err := msg.Header.Encryption.Decapsulate(recipient, nil)
		if err != nil {
			return err
		}
		msgReader = messageDecrypter{
			msg: msg,
			Reader: aead.Reader{
				AEAD: cipher,
				R:    msgReader,
			},
		}
	}

	if comp := msg.Header.Compression; comp != nil {
		decompressed, err := comp.Decompress(msgReader, nil)
		if err != nil {
			return err
		}
		msgReader = decompressed
	}

	msg.Data.Writer = closer
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
	return closer.Close()
}

func (msg *Message) PasswordDecrypt(plaintext io.Writer, sender *quark.PublicKey, passphrase string) error {
	closer := internal.NopCloser(plaintext)
	if !msg.Header.Sender.IsEmpty() {
		closer = internal.ChainCloser(closer, messageVerifier{
			w:   closer,
			msg: msg,
			v:   quark.VerifyStream(sender),
		})
	}

	mr := &messageReader{}
	var msgReader io.Reader = mr
	if msg.Header.Encryption != nil {
		cipher, err := msg.Header.Encryption.Decrypt(passphrase, nil)
		if err != nil {
			return err
		}
		msgReader = messageDecrypter{
			msg: msg,
			Reader: aead.Reader{
				AEAD: cipher,
				R:    msgReader,
			},
		}
	}

	if comp := msg.Header.Compression; comp != nil {
		decompressed, err := comp.Decompress(msgReader, nil)
		if err != nil {
			return err
		}
		msgReader = decompressed
	}

	msg.Data.Writer = closer
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
	return closer.Close()
}

type messageDecrypter struct {
	msg *Message
	aead.Reader
}

func (d messageDecrypter) Read(p []byte) (int, error) {
	n, err := d.Reader.Read(p)
	if err == io.EOF {
		if !mac.Equal(d.msg.Auth.Tag, d.AEAD.Tag(nil)) {
			err = mac.ErrMismatch
		}
	}

	return n, err
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
