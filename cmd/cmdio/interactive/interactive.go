package interactive

import (
	"errors"
	"sort"
	"strconv"
	"time"

	"github.com/karalef/quark-cmd/cmdio"
)

func SelectScheme[T any](prompt string, listAll func() []string, byName func(string) (T, error)) (T, error) {
	all := listAll()
	sort.Strings(all)
	v, err := cmdio.Select(prompt, all)
	if err != nil {
		var empty T
		return empty, err
	}
	return byName(all[v])
}

func ValueOrSelect[T comparable](v T, prompt string, listAll func() []string, byName func(string) (T, error)) (T, error) {
	var empty T
	if v != empty {
		return v, nil
	}
	return SelectScheme(prompt, listAll, byName)
}

func StringOrSelect[T any](v []string, prompt string, listAll func() []string, byName func(string) (T, error)) (T, error) {
	if len(v) > 0 {
		return byName(v[0])
	}
	return SelectScheme(prompt, listAll, byName)
}

func Expires(prompt string) (int64, error) {
	expirations := [...]string{
		"never", "custom",
		"1 month", "3 months", "6 months",
		"1 year", "2 years", "5 years",
	}
	now := time.Now()
	const (
		month = time.Hour * 24 * 30
		year  = time.Hour * 24 * 365
	)
	expToUnix := []int64{
		now.Add(month).Unix(), now.Add(month * 3).Unix(), now.Add(month * 6).Unix(),
		now.Add(year).Unix(), now.Add(year * 2).Unix(), now.Add(year * 5).Unix(),
	}

	i, err := cmdio.Select(prompt, expirations[:])
	if err != nil {
		return 0, err
	}
	if i == 0 {
		return 0, nil
	}
	if i != 1 {
		return expToUnix[i-2], nil
	}

	ystr, err := cmdio.Prompt("Add years", "0", validateUint8)
	if err != nil {
		return 0, err
	}
	mstr, err := cmdio.Prompt("Add months", "0", validateUint8)
	if err != nil {
		return 0, err
	}
	add := year*parseDur(ystr, 8) + month*parseDur(mstr, 8)
	dstr, err := cmdio.Prompt("Add days", "0", func(s string) error {
		d, err := strconv.ParseUint(s, 10, 8)
		if err != nil {
			return err
		}
		if d == 0 && add == 0 {
			return errors.New("expiration time must be minimum 1 day")
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	add += time.Hour * 24 * parseDur(dstr, 32)
	return now.Add(add).Unix(), err
}

func parseDur(s string, bits int) time.Duration {
	v, _ := strconv.ParseUint(s, 10, bits)
	return time.Duration(v)
}

func validateUint8(s string) error {
	_, err := strconv.ParseUint(s, 10, 8)
	return err
}
