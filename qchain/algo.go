package qchain

import "encoding/base64"

type Algorithm interface {
	Name() string
	Description() string
	Input() []DataType
	Output() []DataType
	Execute([]Data) ([]Data, error)
}

var _ Algorithm = (*BaseAlgorithm)(nil)

type BaseAlgorithm struct {
	Func func([]Data) ([]Data, error)
	Algo string
	Desc string
	In   []DataType
	Out  []DataType
}

func (b *BaseAlgorithm) Name() string        { return b.Algo }
func (b *BaseAlgorithm) Description() string { return b.Desc }
func (b *BaseAlgorithm) Input() []DataType   { return b.In }
func (b *BaseAlgorithm) Output() []DataType  { return b.Out }
func (b *BaseAlgorithm) Execute(in []Data) ([]Data, error) {
	if len(in) != len(b.In) {
		return nil, ErrInvalidInput
	}
	for i := range in {
		if !in[i].CanBe(b.In[i]) {
			return nil, ErrInvalidInput
		}
	}
	return b.Func(in)
}

var ToBase64 = BaseAlgorithm{
	Func: func(d []Data) ([]Data, error) {
		return []Data{NewString(base64.StdEncoding.EncodeToString(d[0].binary))}, nil
	},
	Algo: "toBase64",
	Desc: "Converts binary to base64",
	In:   []DataType{DataTypeBinary},
	Out:  []DataType{DataTypeBase64},
}
