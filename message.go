package quark

import (
	"errors"
	"io"
	"time"

	"github.com/karalef/quark/crypto/ae"
	"github.com/karalef/quark/crypto/mac"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/internal"
	"github.com/karalef/quark/pack"
)

// MessageOpts defines options for a message.
type MessageOpts struct {
	// if empty, the DefaultSymmetricScheme is used
	Symmetric SymmetricScheme

	// contains file info
	File File
}

// NewMessage creates a new message.
// If the sender is not nil, the message will be signed.
// If the recipient is not nil, the message will be encrypted.
func NewMessage(plaintext io.Reader, recipient Public, sender Private, opts MessageOpts) (*Message, error) {
	if plaintext == nil {
		panic("NewMessage: nil plaintext")
	}
	if opts.Symmetric.Scheme == nil {
		opts.Symmetric = DefaultSymmetricScheme
	}

	msg := &Message{
		Header: MessageHeader{
			Time: time.Now().Unix(),
			File: opts.File,
		},
		Data: pack.Stream{
			Reader: plaintext,
		},
	}

	if sender != nil {
		signer, err := SignStream(sender, msg.Header.Time)
		if err != nil {
			return nil, err
		}
		msg.Header.Sender = sender.ID()
		msg.Data.Reader = messageSigner{
			r:      msg.Data.Reader,
			msg:    msg,
			signer: signer,
		}
	}

	if recipient != nil {
		cipher, enc, err := Encrypt(opts.Symmetric, recipient)
		if err != nil {
			return nil, err
		}
		msg.Header.Encryption = enc
		msg.Data.Reader = messageEncrypter{
			msg: msg,
			r: ae.Reader{
				AE: cipher,
				R:  msg.Data.Reader,
			},
		}
	}

	return msg, nil
}

type messageEncrypter struct {
	msg *Message
	r   ae.Reader
}

func (e messageEncrypter) Read(p []byte) (n int, err error) {
	n, err = e.r.Read(p)
	if err == io.EOF {
		e.msg.Auth.Tag = e.r.AE.Tag(nil)
	}
	return n, err
}

type messageSigner struct {
	r      io.Reader
	msg    *Message
	signer sign.Signer
}

func (s messageSigner) Read(p []byte) (n int, err error) {
	n, err = s.r.Read(p)
	_, signErr := s.signer.Write(p[:n])
	if signErr != nil {
		return n, signErr
	}
	if err == io.EOF {
		s.msg.Auth.Signature = s.signer.Sign()
	}
	return n, err
}

// DecryptMessage decrypts a message.
func DecryptMessage(plaintext io.Writer, msg *Message, recipient Private, sender Public) error {
	closer := internal.NopCloser(plaintext)
	if !msg.Header.Sender.IsEmpty() {
		verifier, err := VerifyStream(sender, msg.Header.Time)
		if err != nil {
			return err
		}
		closer = internal.ChainCloser(closer, messageVerifier{
			w:   closer,
			msg: msg,
			v:   verifier,
		})
	}
	if msg.Header.Encryption != nil {
		cipher, err := Decrypt(msg.Header.Encryption, recipient)
		if err != nil {
			return err
		}
		closer = internal.ChainCloser(closer, messageDecrypter{
			msg: msg,
			Writer: ae.Writer{
				AE: cipher,
				W:  closer,
			},
		})
	}

	msg.Data.Writer = closer

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
	ae.Writer
}

func (d messageDecrypter) Close() error {
	if !mac.Equal(d.msg.Auth.Tag, d.AE.Tag(nil)) {
		return mac.ErrMismatch
	}
	return nil
}

type messageVerifier struct {
	w   io.Writer
	msg *Message
	v   sign.Verifier
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

// MessageType represents a message type.
type MessageType byte

// message flags and types
const (
	MessageFlagEncrypted MessageType = 1 << iota
	MessageFlagSigned

	// rawly encoded message that is not encrypted and not signed
	MessageTypeRaw = 0x00
	// anonymous message that is only encrypted and not signed
	MessageTypeAnonymous = MessageFlagEncrypted
	// clear-signed message that is only signed and not encrypted
	MessageTypeClearSign = MessageFlagSigned
	// message that is encrypted and signed
	MessageTypeSignedEncrypted = MessageFlagEncrypted | MessageFlagSigned
)

// IsEncrypted returns true if the message is encrypted.
func (t MessageType) IsEncrypted() bool { return t&MessageFlagEncrypted != 0 }

// IsSigned returns true if the message is signed.
func (t MessageType) IsSigned() bool { return t&MessageFlagSigned != 0 }

func (t MessageType) String() string {
	switch t {
	case MessageTypeRaw:
		return "Raw"
	case MessageTypeAnonymous:
		return "Anonymous"
	case MessageTypeClearSign:
		return "Clear-Signed"
	case MessageTypeSignedEncrypted:
		return "Signed and Encrypted"
	default:
		return "unknown"
	}
}

// File contains the file info.
type File struct {
	// name of the file
	Name string `msgpack:"name,omitempty"`

	// time of the last file modification
	Time int64 `msgpack:"time,omitempty"`
}

var _ pack.Packable = (*Message)(nil)
var _ pack.CustomDecoder = (*Message)(nil)

// MessageHeader contains the signature information and encryption parameters.
// It also contains the file info.
type MessageHeader struct {
	// If is not empty, message is signed.
	Sender ID `msgpack:"sender,omitempty"`

	// Time of the message creation.
	// If the message is signed, it is the time of the signature creation.
	Time int64 `msgpack:"time,omitempty"`

	// If is not nil, message is encrypted.
	Encryption *Encryption `msgpack:"encryption,omitempty"`

	// If File.Name is not empty, message represents a file.
	File File `msgpack:"file,omitempty"`
}

// MessageAuth provides authentication and data integrity.
type MessageAuth struct {
	Signature Signature `msgpack:"signature,omitempty"`
	Tag       AuthTag   `msgpack:"auth,omitempty"`
}

// Message contains a message.
type Message struct {
	_msgpack struct{} `msgpack:",as_array"`

	Header MessageHeader

	// if the object is used for unpacking, it will be available only after decryption;
	// Data.Reader is used to store the input stream before decryption.
	Data pack.Stream

	// if the object is used for unpacking, it will be available only after decryption.
	Auth MessageAuth
}

// DecodeMsgpack implements pack.CustomDecoder interface.
// It decodes only a header and stores the input stream.
func (m *Message) DecodeMsgpack(dec *pack.Decoder) error {
	dec.DecodeArrayLen()
	if err := dec.Decode(&m.Header); err != nil {
		return err
	}
	// store the input stream to continue unpacking
	m.Data.Reader = dec.Buffered()
	return nil
}

// ErrBrokenMessage is returned when the message is broken.
type ErrBrokenMessage struct {
	Description string
}

func (err ErrBrokenMessage) Error() string {
	return "broken message: " + err.Description
}

// PacketTag implements pack.Packable interface.
func (*Message) PacketTag() pack.Tag { return PacketTagMessage }

// Type returns the message type.
func (m *Message) Type() (typ MessageType) {
	if m.Header.Encryption != nil {
		typ |= MessageFlagEncrypted
	}
	if !m.Header.Sender.IsEmpty() {
		typ |= MessageFlagSigned
	}
	return
}
