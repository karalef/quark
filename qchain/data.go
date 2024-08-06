package qchain

import "errors"

type DataType uint8

const (
	DataTypeBinary DataType = iota
	DataTypeString
	DataTypeBase64
	DataTypeHex

	DataTypeStreamFlag = 1 << 7
)

var (
	ErrInvalidInput = errors.New("invalid input")
)

func NewString(str string) Data {
	return Data{str: str}
}

type Data struct {
	str    string
	binary []byte
}

func (d *Data) CanBe(t DataType) bool {
	return false
}
