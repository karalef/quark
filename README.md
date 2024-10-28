# Quark

Quark is a post-quantum crypto-secure crypto library.

## Why?

*"Imagine that it's fifteen years from now. Somebody announces that he's built a large quantum computer. RSA is dead. DSA is dead. Elliptic curves, hyperelliptic curves, class groups, whatever, dead, dead, dead. So users are going to run around screaming and say 'Oh my God, what do we do?'..."* - https://pqcrypto.org

## Usage

### [Using go](https://pkg.go.dev/cmd/go#hdr-Compile_and_install_packages_and_dependencies)
```sh
go get github.com/karalef/quark
```

```go
package main

import (
    "time"

    "github.com/karalef/quark"
    "github.com/karalef/quark/crypto/sign"
)

func main() {
    key, err := quark.Generate(sign.EDDilithium3, 365*24*time.Hour)
    ...
}
```
