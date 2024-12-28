package utils

func Default[T comparable](v T, def T) (empty T) {
	if v == empty {
		return def
	}

	return v
}

func DefaultE[T comparable](v T, f func() (T, error)) (empty T, err error) {
	if v != empty {
		return v, nil
	}
	return f()
}
