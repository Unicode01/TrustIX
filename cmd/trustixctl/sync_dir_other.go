//go:build !windows

package main

import (
	"errors"
	"os"
)

func syncOutputDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}
