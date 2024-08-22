package internal

func MapValue[T any](m map[string]any, key string) T {
	if v, ok := m[key]; ok {
		return v.(T)
	}
	var zero T
	return zero
}
