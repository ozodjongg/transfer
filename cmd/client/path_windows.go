//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

// ensureExecutableOnUserPath adds the directory containing client.exe to the
// current Windows user's PATH. It does not require administrator privileges.
// Existing terminals keep their old environment; newly opened terminals see
// the updated PATH.
func ensureExecutableOnUserPath() (bool, string, error) {
	dir, err := executableDir()
	if err != nil {
		return false, "", fmt.Errorf("client papkasini aniqlab bo'lmadi: %w", err)
	}

	// Fast path: if this process already inherited the directory in PATH, no
	// persistent write is needed in normal use.
	if pathContainsDir(os.Getenv("PATH"), dir) {
		return false, dir, nil
	}

	// Use the per-user environment store via .NET. This avoids admin rights and
	// avoids SETX's historical PATH truncation/expansion pitfalls.
	const script = `$target = [System.IO.Path]::GetFullPath($args[0]); ` +
		`$current = [Environment]::GetEnvironmentVariable('Path','User'); ` +
		`$entries = @(); if (-not [string]::IsNullOrWhiteSpace($current)) { $entries = $current -split ';' }; ` +
		`$found = $false; foreach ($entry in $entries) { ` +
		`if (-not [string]::IsNullOrWhiteSpace($entry)) { ` +
		`$expanded = [Environment]::ExpandEnvironmentVariables($entry.Trim().Trim('"')); ` +
		`try { $expanded = [System.IO.Path]::GetFullPath($expanded) } catch {}; ` +
		`if ([string]::Equals($expanded.TrimEnd('\\'), $target.TrimEnd('\\'), [System.StringComparison]::OrdinalIgnoreCase)) { $found = $true; break } } }; ` +
		`if (-not $found) { ` +
		`if ([string]::IsNullOrWhiteSpace($current)) { $newPath = $target } else { $newPath = $current.TrimEnd(';') + ';' + $target }; ` +
		`[Environment]::SetEnvironmentVariable('Path',$newPath,'User'); Write-Output 'ADDED' ` +
		`} else { Write-Output 'EXISTS' }`

	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script, dir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false, dir, fmt.Errorf("Windows User PATH yangilanmadi: %w (%s)", err, strings.TrimSpace(string(out)))
	}

	added := strings.Contains(strings.ToUpper(string(out)), "ADDED")
	if added {
		notifyEnvironmentChanged()
	}

	if added && !pathContainsDir(os.Getenv("PATH"), dir) {
		current := os.Getenv("PATH")
		if current == "" {
			_ = os.Setenv("PATH", dir)
		} else {
			_ = os.Setenv("PATH", current+";"+dir)
		}
	}
	return added, dir, nil
}

func notifyEnvironmentChanged() {
	const (
		hwndBroadcast    = 0xffff
		wmSettingChange  = 0x001A
		smtoAbortIfHung  = 0x0002
		notificationWait = 5000
	)

	user32 := syscall.NewLazyDLL("user32.dll")
	sendMessageTimeoutW := user32.NewProc("SendMessageTimeoutW")
	environment, err := syscall.UTF16PtrFromString("Environment")
	if err != nil {
		return
	}
	var result uintptr
	_, _, _ = sendMessageTimeoutW.Call(
		uintptr(hwndBroadcast),
		uintptr(wmSettingChange),
		0,
		uintptr(unsafe.Pointer(environment)),
		uintptr(smtoAbortIfHung),
		uintptr(notificationWait),
		uintptr(unsafe.Pointer(&result)),
	)
}
