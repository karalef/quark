package quark

func EncryptMessage(message []byte, to PublicKeyset, signWith PrivateKeyset) (*Message, error) {
	if len(message) == 0 {
		return nil, nil
	}

	cipherkey, ciphertext, err := Encrypt(message, to)
	if err != nil {
		return nil, err
	}

	msg := &Message{
		Key:     cipherkey,
		Message: ciphertext,
	}

	if signWith == nil {
		return msg, nil
	}

	signature, err := signWith.Sign(message)
	if err != nil {
		return nil, err
	}

	msg.Signature = signature
	msg.Fingerprint = PublicFingerprint(signWith)

	return msg, nil
}

func DecryptMessage(msg *Message, to PrivateKeyset) ([]byte, error) {
	if msg == nil {
		return nil, nil
	}

	return Decrypt(msg.Message, msg.Key, to)
}

// Message contains an encrypted message.
type Message struct {
	// sender`s public key fingerprint
	Fingerprint Fingerprint

	// signature
	Signature []byte

	// encrypted session key
	Key []byte

	// encrypted message
	Message []byte
}

// IsAnonymous returns true if the message is anonymous.
func (m Message) IsAnonymous() bool { return !m.IsSigned() && m.Fingerprint == Fingerprint{} }

func (m Message) IsSigned() bool { return len(m.Signature) != 0 }
