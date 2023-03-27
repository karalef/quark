package keys

import (
	"encoding/hex"
	"os"
	"strings"

	"github.com/karalef/quark"
	"github.com/karalef/wfs"
)

func KeyID(ks quark.PublicKeyset) string {
	return KeyIDByFingerprint(quark.PublicFingerprint(ks))
}
func KeyIDByFingerprint(fp quark.Fingerprint) string {
	return hex.EncodeToString(fp[:8])
}

func Fingerprint(ks quark.PublicKeyset) string {
	fp := quark.PublicFingerprint(ks)
	return fp.String()
}

func findKeysetFile(fs wfs.Filesystem, keyID string) (string, error) {
	dir, err := fs.ReadDir(".")
	if err != nil {
		return "", err
	}
	for _, entry := range dir {
		if strings.TrimSuffix(entry.Name(), keysetExt) == keyID {
			return entry.Name(), nil
		}
	}
	return "", os.ErrNotExist
}
