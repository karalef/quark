package utils

import "time"

func FormatUnix(t int64) string {
	return time.Unix(t, 0).Format("02 Jan 2006 15:04")
}
