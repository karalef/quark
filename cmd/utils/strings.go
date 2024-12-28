package utils

// LCP returns the longest common prefix of the given strings.
func LCP(strs []string) string {
	if len(strs) == 0 {
		return ""
	}
	if len(strs) == 1 {
		return strs[0]
	}
	prefix := strs[0]
	for _, str := range strs[1:] {
		l := min(len(prefix), len(str))
		if l == 0 {
			return ""
		}
		for i := 0; i < l; i++ {
			if prefix[i] != str[i] {
				prefix = prefix[:i]
				break
			}
		}
	}
	return prefix
}
