package secretsharing_test

import (
	"testing"

	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/secretsharing"
)

func TestSharing(t *testing.T) {
	g := secretsharing.P521
	secret := make([]byte, g.Size())
	secret[1] = 123
	secret[len(secret)-2] = 246
	sharing := g.New(3, secret[:])

	shares := sharing.Share(10)
	commit := sharing.Commit()

	for i := range shares {
		if !g.Verify(3, shares[i], commit) {
			t.Fatalf("failed to verify share %d", i)
		}
	}

	recovered := g.Recover(3, shares)
	if !crypto.Equal(recovered, secret[:]) {
		t.Fatal("failed to recover secret")
	}
}
