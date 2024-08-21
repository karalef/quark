package main

import (
	"context"
	"os"
	"path/filepath"

	"github.com/karalef/quark/cmd/cmdio"
	"github.com/karalef/quark/cmd/enc"
	"github.com/karalef/quark/cmd/keys"
	"github.com/karalef/quark/cmd/keystore"
	"github.com/karalef/quark/cmd/keystore/dir"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:                   "quark",
		Version:                "0.2.0",
		Usage:                  "post-quantum crypto-secured digital identity manager",
		UseShortOptionHandling: true,
		Writer:                 os.Stderr,
		ErrWriter:              os.Stderr,
		DefaultCommand:         enc.DecryptCMD.Name,
		Commands: []*cli.Command{
			keys.GenerateCMD,
			keys.ListCMD,
			keys.ImportCMD,
			keys.ExportCMD,
			keys.DeleteCMD,
			enc.EncryptCMD,
			enc.DecryptCMD,
		},
	}

	home, err := os.UserHomeDir()
	if err != nil {
		cmdio.Status(err)
		os.Exit(1)
	}
	root := filepath.Join(home, ".quark")

	ks, err := dir.New(dir.Config{
		Root:           root,
		PublicDir:      "public",
		PrivateDir:     "private",
		PublicFileExt:  ".qpk",
		PrivateFileExt: ".qsk",
	})
	if err != nil {
		cmdio.Status(err)
		os.Exit(1)
	}

	ctx := context.WithValue(context.Background(), keystore.ContextKey, ks)
	if err := app.RunContext(ctx, os.Args); err != nil {
		cmdio.Status(err)
		os.Exit(1)
	}
}
