package interactive

import (
	"errors"

	"github.com/karalef/quark-cmd/app"
	"github.com/karalef/quark-cmd/cmdio"
	"github.com/karalef/quark/extensions/subkey"
)

func SelectKey(prompt string, keys []*app.Key) (*app.Key, error) {
	if len(keys) == 0 {
		return nil, errors.New("no keys")
	}
	ids := make([]string, len(keys))
	for i := range keys {
		ids[i] = keys[i].ID().String()
	}
	i, err := cmdio.Select(prompt, ids)
	if err != nil {
		return nil, err
	}
	return keys[i], nil
}

func SelectSubkey(prompt string, subs []subkey.Subkey) (subkey.Subkey, error) {
	if len(subs) == 0 {
		return subkey.Subkey{}, errors.New("no subkeys")
	}
	ids := make([]string, len(subs))
	for i := range subs {
		ids[i] = subs[i].ID().String()
	}
	i, err := cmdio.Select(prompt, ids)
	if err != nil {
		return subkey.Subkey{}, err
	}
	return subs[i], nil
}
