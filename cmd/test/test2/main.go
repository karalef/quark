package main

import (
	"encoding/binary"
	"math"
	"time"
)

func main() {
	println(len(binary.AppendVarint(nil, time.Now().Unix())))
	println(len(binary.AppendVarint(nil, math.MaxInt64)))
}
