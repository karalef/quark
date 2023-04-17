package keys

import (
	"errors"
	"fmt"
	"os"

	"github.com/karalef/quark/cmd/storage"
	"github.com/urfave/cli/v2"
)

var DeleteCMD = &cli.Command{
	Name:     "delete",
	Usage:    "delete a keyset",
	Category: "key management",
	Aliases:  []string{"del"},
	Action: func(c *cli.Context) error {
		if !c.Args().Present() {
			return errors.New("must specify a keyset to delete")
		}
		keyID := c.Args().First()

		_, err := DeleteByID(keyID)
		if err != nil {
			return err
		}

		fmt.Println("deleted", keyID)
		return nil
	},
}

func DeleteByID(id string) (found bool, err error) {
	privks, err := findPrivate(id)
	if err != nil && err != os.ErrNotExist {
		return false, err
	}
	if privks != "" {
		err = storage.PrivateFS().Remove(privks)
		if err != nil {
			return true, err
		}
	}

	pubks, err := findPublic(id)
	if err != nil {
		if err == os.ErrNotExist && privks != "" {
			return true, errors.New("private keyset was found but public was not")
		}
		return false, err
	}
	return true, storage.PublicFS().Remove(pubks)
}
