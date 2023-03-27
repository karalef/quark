package keys

import (
	"fmt"

	"github.com/karalef/quark"
	"github.com/karalef/quark/cmd/storage"
	"github.com/karalef/wfs"
	"github.com/urfave/cli/v2"
)

var ListCMD = &cli.Command{
	Name:  "list",
	Usage: "list keys",
	Action: func(c *cli.Context) error {
		priv, pub, err := listAll()
		if err != nil {
			return err
		}
		PrintKeys(priv, pub)
		return nil
	},
}

type KeysetEntry struct {
	ID          string
	Fingerprint string
	Name        string
	Email       string
	Scheme      string
}

func listAll() (priv, pub []KeysetEntry, err error) {
	priv, err = listFS(storage.PrivateKeysFS())
	if err != nil {
		return nil, nil, err
	}
	pub, err = listFS(storage.PublicKeysFS())
	if err != nil {
		return nil, nil, err
	}
	return priv, pub, nil
}

func listFS(fs wfs.Filesystem) ([]KeysetEntry, error) {
	dir, err := fs.ReadDir(".")
	if err != nil {
		return nil, err
	}
	list := make([]KeysetEntry, 0, len(dir))
	for _, entry := range dir {
		if entry.IsDir() {
			continue
		}
		f, err := fs.Open(entry.Name())
		if err != nil {
			return nil, err
		}
		e, err := loadKeysetEntry(f)
		if err != nil {
			return nil, err
		}

		list = append(list, e)
	}
	return list, err
}

func loadKeysetEntry(f wfs.File) (KeysetEntry, error) {
	pk, err := loadKeyset(f)
	if err != nil {
		return KeysetEntry{}, err
	}
	e := KeysetEntry{
		Name:   pk.Identity.Name,
		Email:  pk.Identity.Email,
		Scheme: pk.Scheme,
	}

	var ks quark.PublicKeyset
	if pk.IsPrivate {
		ks, err = pk.UnpackPrivate()
	} else {
		ks, err = pk.UnpackPublic()
	}
	if err != nil {
		return KeysetEntry{}, err
	}

	e.Fingerprint = Fingerprint(ks)
	e.ID = KeyID(ks)
	return e, nil
}

func PrintKeys(priv, pub []KeysetEntry) {
	if len(priv) > 0 {
		fmt.Println("private keys:")
		for _, k := range priv {
			printKey(k)
		}
	}

	if len(pub) > 0 {
		fmt.Println("\npublic keys:")
		for _, k := range pub {
			printKey(k)
		}
	}
}

func printKey(k KeysetEntry) {
	fmt.Printf("%s\t%s <%s>\n\t%s\t%s\n", k.ID, k.Name, k.Email, k.Scheme, k.Fingerprint)
}
