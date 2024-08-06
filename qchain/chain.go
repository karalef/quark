package qchain

type Chain struct {
}

func (c *Chain) Execute(input []Data) ([]Data, error) {
	return nil, nil
}

func (c *Chain) Input() []DataType {
	return nil
}

func (c *Chain) Output() []DataType {
	return nil
}
