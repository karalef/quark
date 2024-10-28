package backup

import (
	"errors"

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
	enc, pp, err := key.NewEncrypter(passphrase, source, params)
	if err != nil {
		return nil, err
	}
	b := &Backup{
		Key:        data.Key,
		Passphrase: pp,
		Subkeys:    make([]key.Element, len(data.Subkeys)),
	}
	b.Secret, err = enc.Encrypt(data.Secret)
	if err != nil {
		return nil, err
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
	encrypted.Passphrase
	Key     *quark.Key    `msgpack:"key"`
	Subkeys []key.Element `msgpack:"subkeys"`
	Secret  key.Element   `msgpack:"secret"`
}

// PacketTag returns the packet tag.
func (*Backup) PacketTag() pack.Tag { return PacketTagBackup }

// Decrypt decrypts the backup with the given passphrase.
func (b Backup) Decrypt(passphrase string) (BackupData, error) {
	crypter, err := b.Passphrase.NewCrypter(passphrase)
	if err != nil {
		return BackupData{}, err
	}

	bd := BackupData{Key: b.Key}
	key, err := b.Secret.Decrypt(crypter)
	if err != nil {
		return BackupData{}, err
	}
	var ok bool
	bd.Secret, ok = key.(sign.PrivateKey)
	if !ok {
		return BackupData{}, errInvalidKeyType
	}

	bd.Subkeys = make([]crypto.Key, len(b.Subkeys))
	for i, sub := range b.Subkeys {
		key, err := sub.Decrypt(crypter)
		if err != nil {
			return BackupData{}, err
		}
		bd.Subkeys[i] = key
	}
	return bd, nil
}

var errInvalidKeyType = errors.New("invalid key type")
