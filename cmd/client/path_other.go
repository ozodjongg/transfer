//go:build !windows

package main

func ensureExecutableOnUserPath() (bool, string, error) {
	return false, "", nil
}
