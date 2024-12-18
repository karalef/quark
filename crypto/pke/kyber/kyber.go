package kyber

type PublicKey interface {
	EncryptTo(ct, pt, seed []byte)
	Pack([]byte)
}

type PrivateKey interface {
	privateKey[PrivateKey]
}

type Scheme interface {
	DeriveKey([]byte) (PublicKey, PrivateKey)
	UnpackPublic([]byte) PublicKey
	UnpackPrivate([]byte) PrivateKey
	CiphertextSize() int
	PlaintextSize() int
	EncryptionSeedSize() int
	PrivateKeySize() int
	PublicKeySize() int
	SeedSize() int
}

type privKey interface {
	DecryptTo(pt, ct []byte)
	Pack([]byte)
}

type privateKey[T privKey] interface {
	privKey
	Equal(T) bool
}

type wPrivateKey[SK privateKey[SK]] struct{ sk SK }

func (w wPrivateKey[SK]) DecryptTo(pt, ct []byte) { w.sk.DecryptTo(pt, ct) }
func (w wPrivateKey[SK]) Pack(b []byte)           { w.sk.Pack(b) }

func (w wPrivateKey[SK]) Equal(other PrivateKey) bool {
	s, ok := other.(SK)
	return ok && w.sk.Equal(s)
}

type kyberScheme[PK PublicKey, SK privateKey[SK]] struct {
	derive  func(seed []byte) (PK, SK)
	public  func([]byte) PK
	private func([]byte) SK
	sk, pk  int
	ct, pt  int
	es, s   int
}

func (s kyberScheme[_, SK]) DeriveKey(seed []byte) (PublicKey, PrivateKey) {
	pk, sk := s.derive(seed)
	return pk, wPrivateKey[SK]{sk: sk}
}

func (s kyberScheme[_, SK]) UnpackPrivate(key []byte) PrivateKey {
	return wPrivateKey[SK]{sk: s.private(key)}
}

func (s kyberScheme[_, _]) UnpackPublic(key []byte) PublicKey { return s.public(key) }

func (s kyberScheme[_, _]) CiphertextSize() int     { return s.ct }
func (s kyberScheme[_, _]) PlaintextSize() int      { return s.pt }
func (s kyberScheme[_, _]) EncryptionSeedSize() int { return s.es }
func (s kyberScheme[_, _]) PrivateKeySize() int     { return s.sk }
func (s kyberScheme[_, _]) PublicKeySize() int      { return s.pk }
func (s kyberScheme[_, _]) SeedSize() int           { return s.s }
