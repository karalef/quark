# Quark

Quark is a post-quantum cryptography tool inspired by GnuPG with a modern cli interface.

## Why?

*"Imagine that it's fifteen years from now. Somebody announces that he's built a large quantum computer. RSA is dead. DSA is dead. Elliptic curves, hyperelliptic curves, class groups, whatever, dead, dead, dead. So users are going to run around screaming and say 'Oh my God, what do we do?'..."* - https://pqcrypto.org

## Installation

### [Using go](https://pkg.go.dev/cmd/go#hdr-Compile_and_install_packages_and_dependencies)
```sh
go install github.com/karalef/quark/cmd/quark@v0.1.2
```

### Clone & build
```sh
git clone https://github.com/karalef/quark

cd quark

go build -o path/to/binary ./cmd/quark
```