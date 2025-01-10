package backup

import (
	"github.com/karalef/quark"
	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/encrypted"
	"github.com/karalef/quark/pack"
)

// PacketTagBackup is a backup packet tag.
const PacketTagBackup = 0x07

func init() {
	pack.RegisterPacketType(pack.NewType((*Backup)(nil), "backup"))
}

// BackupData contains backup data.
type BackupData struct {
	Key     *quark.Key
	Certs   []quark.Any
	Secrets []crypto.Key
}

// New creates a new backup and encrypts it with the given passphrase.
func New(data BackupData,
	passphrase string,
	source encrypted.NonceSource,
	params encrypted.PassphraseParams,
) (*Backup, error) {
	b := &Backup{
		Key:        data.Key,
		Certs:      data.Certs,
		Secrets:    make([]encrypted.Key[crypto.Key], len(data.Secrets)),
		Passphrase: params.New(),
	}
	enc, err := encrypted.NewKeyEncrypter[crypto.Key](passphrase, source, b.Passphrase)
	if err != nil {
		return nil, err
	}
	for i, sub := range data.Secrets {
		b.Secrets[i], err = enc.Encrypt(sub)
		if err != nil {
			return nil, err
		}
	}
	return b, nil
}

// Backup contains the key with encrypted private keys.
type Backup struct {
	Key        *quark.Key                  `msgpack:"key"`
	Certs      []quark.Any                 `msgpack:"certs"`
	Passphrase encrypted.Passphrase        `msgpack:"passphrase"`
	Secrets    []encrypted.Key[crypto.Key] `msgpack:"secret"`
}

// PacketTag returns the packet tag.
func (*Backup) PacketTag() pack.Tag { return PacketTagBackup }

// Decrypt decrypts the backup with the given passphrase.
func (b Backup) Decrypt(passphrase string) (BackupData, error) {
	crypter, err := b.Passphrase.NewCrypter(passphrase)
	if err != nil {
		return BackupData{}, err
	}
	secrets := make([]crypto.Key, len(b.Secrets))
	for i, sub := range b.Secrets {
		secrets[i], err = sub.DecryptKey(crypter)
		if err != nil {
			return BackupData{}, err
		}
	}
	return BackupData{
		Key:     b.Key,
		Certs:   b.Certs,
		Secrets: secrets,
	}, nil
}
