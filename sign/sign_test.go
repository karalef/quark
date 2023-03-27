package sign

import (
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

var testmsg = []byte(`Lorem ipsum dolor sit amet, consectetur adipiscing elit. Vestibulum finibus, felis eu egestas iaculis, massa enim laoreet magna, sed lobortis purus mi at lacus. Duis eleifend, ex eget interdum egestas, nulla tortor consectetur leo, facilisis aliquam lectus nunc et mi. Suspendisse at dapibus dolor. Suspendisse potenti. Sed tempus arcu vitae magna hendrerit, eu sagittis augue maximus. Aliquam egestas enim eu elit pretium, vel tempor nisi vulputate. Curabitur suscipit dui orci, quis laoreet ante scelerisque quis. Suspendisse vehicula arcu sed ullamcorper sollicitudin. Nulla sagittis est vitae cursus maximus. Duis commodo massa et tellus venenatis feugiat. Donec interdum neque in nulla facilisis rutrum. Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Vivamus mattis lectus sodales turpis tempor placerat. Morbi et libero id ligula placerat suscipit. Suspendisse potenti.`)

func TestSign(t *testing.T) {
	t.Logf("testing %s", Dilithium3)
	alg := Dilithium3
	scheme := alg.Scheme()
	if scheme == nil {
		t.Fatal(ErrInvalidKeyAlgorithm)
	}

	priv, pub, err := scheme.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	sum := sha256.Sum256(testmsg)
	signature, err := priv.Sign(sum[:])
	if err != nil {
		t.Fatal(err)
	}

	v, err := pub.Verify(sum[:], signature)
	if err != nil {
		t.Fatal(err)
	}
	if !v {
		t.Fatal("verification failed")
	}

	t.Log("signature has been verified")
}
