package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func main() {
	dl, err := countDirLines(os.Args[1], ".go")
	if err != nil {
		panic(err)
	}

	dl.print(0)
}

type dirLines struct {
	nest  []dirLines
	files map[string]uint64
	total uint64
	name  string
}

func (d dirLines) print(nest uint) {
	prefix := strings.Repeat("  ", int(nest))
	fmt.Println(prefix + d.name + " " + strconv.FormatUint(d.total, 10))
	for k, v := range d.files {
		fmt.Println(prefix, "|", k+" "+strconv.FormatUint(v, 10))
	}
	for i := range d.nest {
		d.nest[i].print(nest + 1)
	}
}

func countDirLines(path, ext string) (dirLines, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return dirLines{}, err
	}
	dl := dirLines{
		name:  path,
		files: make(map[string]uint64),
	}
	for _, entry := range entries {
		if entry.Type().IsDir() {
			d, err := countDirLines(filepath.Join(path, entry.Name()), ext)
			if err != nil {
				return dirLines{}, err
			}
			if d.total != 0 {
				dl.nest = append(dl.nest, d)
				dl.total += d.total
			}
			continue
		}
		if filepath.Ext(entry.Name()) == ext {
			lines, err := countIn(filepath.Join(path, entry.Name()))
			if err != nil {
				return dirLines{}, err
			}
			dl.files[entry.Name()] = lines
			dl.total += lines
		}
	}

	return dl, nil
}

func countIn(path string) (uint64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var c uint64
	for scanner.Scan() {
		c++
	}
	return c, scanner.Err()
}
