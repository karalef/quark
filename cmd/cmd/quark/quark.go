package quark

import (
	"context"
	"os"
	"path/filepath"

	"github.com/karalef/quark-cmd/app"
	"github.com/karalef/quark-cmd/cmd/quark/keys"
	"github.com/karalef/quark-cmd/cmd/quark/messages"
	"github.com/karalef/quark-cmd/cmd/quark/tools"
	"github.com/karalef/quark-cmd/cmdio"
	"github.com/karalef/quark-cmd/config"
	"github.com/karalef/quark-cmd/storage"
	"github.com/karalef/quark-cmd/storage/keystore/dir"
	"github.com/spf13/cobra"
)

var rootFlags struct {
	config string
}

func init() {
	rootCmd.SetOut(os.Stderr)

	rootCmd.PersistentFlags().StringVarP(&rootFlags.config, "config", "c", "", "config file (default is $HOME/.quark/config.yaml)")

	// keys
	rootCmd.AddGroup(keys.Group)
	rootCmd.AddCommand(keys.Gen)
	rootCmd.AddCommand(keys.Import)
	rootCmd.AddCommand(keys.Export)
	rootCmd.AddCommand(keys.Edit)
	rootCmd.AddCommand(keys.Bind)
	rootCmd.AddCommand(keys.List)

	// messages
	rootCmd.AddGroup(messages.Group)
	rootCmd.AddCommand(messages.Encrypt)
	rootCmd.AddCommand(messages.Decrypt)

	// tools
	rootCmd.AddCommand(tools.Tools)

	rootCmd.AddCommand(&cobra.Command{
		Use:    "completion",
		Hidden: true,
	})
}

var rootCmd = &cobra.Command{
	Use:     "quark",
	Version: "0.0.1",
	Short:   "post-quantum crypto-secured digital identity manager",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		root, err := storage.Init(".quark")
		if err != nil {
			exit(1, err)
		}

		if err = root.MkdirAll("public", 0o700); err != nil {
			exit(1, err)
		}
		if err = root.MkdirAll("private", 0o700); err != nil {
			exit(1, err)
		}

		pub := dir.NewPubring(root.ChangeDir("public"), config.KeyExtension)
		sec := dir.NewSecrets(root.ChangeDir("private"), config.PrivateKeyExtension)

		var cfg config.Config
		if rootFlags.config != "" {
			fs := storage.OpenOS(filepath.Dir(rootFlags.config))
			cfg, err = storage.LoadConfig(fs, filepath.Base(rootFlags.config))
		} else {
			cfg, err = storage.LoadConfig(root, "config.yaml")
		}
		if err != nil {
			exit(1, err)
		}

		cmd.SetContext(app.Context(cmd.Context(), app.New(pub, sec, cfg)))
	},
}

func exit(code int, err any) {
	cmdio.Println(err)
	os.Exit(code)
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.ExecuteContext(context.Background()); err != nil {
		exit(1, err)
	}
}
