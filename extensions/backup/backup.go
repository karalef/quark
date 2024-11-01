package backup

import (
	"github.com/karalef/quark"
	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/encrypted"
	"github.com/karalef/quark/encrypted/key"
	"github.com/karalef/quark/pack"
)

// PacketTagBackup is a backup packet tag.
const PacketTagBackup = 0x04

func init() {
	pack.RegisterPacketType(pack.NewType((*Backup)(nil), "backup", "QUARK BACKUP"))
}

// BackupData contains backup data.
type BackupData struct {
	Key     *quark.Key
	Secret  sign.PrivateKey
	Subkeys []crypto.Key
}

// New creates a new backup and encrypts it with the given passphrase.
func New(data BackupData,
	passphrase string,
	source encrypted.NonceSource,
	params encrypted.PassphraseParams,
) (*Backup, error) {
	pass := params.New()
	enc, err := key.NewEncrypter(passphrase, source, pass)
	if err != nil {
		return nil, err
	}
	sec, err := enc.Encrypt(data.Secret)
	if err != nil {
		return nil, err
	}
	b := &Backup{
		Key:     data.Key,
		Subkeys: make([]key.Sub, len(data.Subkeys)),
		Secret: key.Key{
			Passphrase: pass,
			Sub:        sec,
		},
	}
	for i, sub := range data.Subkeys {
		b.Subkeys[i], err = enc.Encrypt(sub)
		if err != nil {
			return nil, err
		}
	}
	return b, nil
}

// Backup contains the key with encrypted private keys.
type Backup struct {
	Key     *quark.Key `msgpack:"key"`
	Subkeys []key.Sub  `msgpack:"subkeys"`
	Secret  key.Key    `msgpack:"secret"`
}

// PacketTag returns the packet tag.
func (*Backup) PacketTag() pack.Tag { return PacketTagBackup }

// Decrypt decrypts the backup with the given passphrase.
func (b Backup) Decrypt(passphrase string) (BackupData, error) {
	crypter, err := b.Secret.Passphrase.NewCrypter(passphrase)
	if err != nil {
		return BackupData{}, err
	}
	secret, err := b.Secret.Sub.DecryptSign(crypter)
	if err != nil {
		return BackupData{}, err
	}

	subkeys := make([]crypto.Key, len(b.Subkeys))
	for i, sub := range b.Subkeys {
		key, err := sub.DecryptKey(crypter)
		if err != nil {
			return BackupData{}, err
		}
		subkeys[i] = key
	}
	return BackupData{
		Key:     b.Key,
		Secret:  secret,
		Subkeys: subkeys,
	}, nil
}
