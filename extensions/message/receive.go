package message

import (
	"errors"
	"io"

	"github.com/karalef/quark"
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/kem"
	"github.com/karalef/quark/crypto/mac"
	"github.com/karalef/quark/crypto/pke"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/pack"
)

// Decrypt contains the parameters to decrypt the message.
type Decrypt struct {
	// Issuer is used to verify the signature.
	Issuer sign.PublicKey
	// GroupRecipient is used to decrypt the message.
	GroupRecipient pke.PrivateKey
	// Recipient is used to decrypt the message.
	Recipient kem.PrivateKey
	// Password is used to decrypt the message.
	Password string
	// Derived is used to decrypt the message.
	Derived []byte
}

func (d Decrypt) decrypt(enc *Encryption) (aead.Cipher, error) {
	switch {
	case enc.IsEncapsulated():
		if d.Recipient == nil {
			return nil, errors.New("message is public key encrypted but no recipient's private key provided")
		}
		return enc.Decapsulate(d.Recipient, nil)
	case enc.IsGroup():
		if d.GroupRecipient == nil {
			return nil, errors.New("message is encrypted for group but no group recipient's private key provided")
		}
		return enc.DecryptFor(d.GroupRecipient, nil)
	case enc.IsPassphrased():
		if d.Password == "" {
			return nil, errors.New("message is encrypted with password but no password provided")
		}
		return enc.DecryptPassphrase(d.Password, nil)
	case enc.IsDerived():
		if d.Derived == nil {
			return nil, errors.New("message is encrypted with derived key but no derived key provided")
		}
		return enc.Decrypt(d.Derived, nil)
	}
	return nil, errors.New("invalid message encryption")
}

func (msg *Message) Decrypt(plain io.Writer, decrypt Decrypt) error {
	// Verify signature
	var verifier *quark.Verifier
	msg.Data.Writer = plain
	if !msg.Header.Sender.IsEmpty() && decrypt.Issuer != nil {
		verifier = quark.Verify(decrypt.Issuer)
		msg.Data.Writer = io.MultiWriter(plain, verifier)
	}

	// Decrypt
	var cipher aead.Cipher
	msgReader := io.Reader(&msg.Data)
	if enc := msg.Header.Encryption; enc != nil {
		var err error
		cipher, err = decrypt.decrypt(enc)
		if err != nil {
			return err
		}
		msgReader = aead.Reader{
			AEAD: cipher,
			R:    msgReader,
		}
	}

	// Decompress
	if comp := msg.Header.Compression; comp != nil {
		dec, err := comp.Decompress(msgReader, nil)
		if err != nil {
			return err
		}
		msgReader = dec
	}

	msg.Data.R = msgReader

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

	// Verify tag
	if !mac.Equal(msg.Auth.Tag, cipher.Tag(nil)) {
		return mac.ErrMismatch
	}

	// Verify signature
	if verifier == nil {
		return nil
	}
	ok, err := verifier.Verify(msg.Auth.Signature)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("the signature cannot be verified, it may have been forged")
	}
	return nil
}
