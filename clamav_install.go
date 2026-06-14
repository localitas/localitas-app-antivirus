package antivirus

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

func DefaultSocketPath() string {
	if runtime.GOOS == "darwin" {
		return "/opt/homebrew/var/run/clamav/clamd.sock"
	}
	return "/var/run/clamav/clamd.ctl"
}

func DefaultConfPath() string {
	if runtime.GOOS == "darwin" {
		return "/opt/homebrew/etc/clamav/clamd.conf"
	}
	return "/etc/clamav/clamd.conf"
}

func IsClamAVInstalled() bool {
	_, err := exec.LookPath("clamd")
	return err == nil
}

func IsClamdRunning(socketPath string) bool {
	scanner := NewScanner(socketPath)
	_, err := scanner.Ping()
	return err == nil
}

func InstallClamAV() error {
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("auto-install only supported on macOS via Homebrew")
	}

	if _, err := exec.LookPath("brew"); err != nil {
		return fmt.Errorf("Homebrew not found, please install clamav manually")
	}

	log.Printf("[Antivirus] Installing ClamAV via Homebrew...")
	cmd := exec.Command("brew", "install", "clamav")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("brew install clamav: %w", err)
	}

	log.Printf("[Antivirus] ClamAV installed successfully")
	return nil
}

func EnsureClamdConf(socketPath string) error {
	confPath := DefaultConfPath()

	if _, err := os.Stat(confPath); err == nil {
		data, _ := os.ReadFile(confPath)
		if strings.Contains(string(data), "LocalSocket") && !strings.Contains(string(data), "Example") {
			return nil
		}
	}

	sockDir := filepath.Dir(socketPath)
	os.MkdirAll(sockDir, 0755)

	conf := fmt.Sprintf(`LocalSocket %s
LocalSocketMode 660
FixStaleSocket yes
MaxDirectoryRecursion 20
MaxScanSize 100M
MaxFileSize 25M
MaxRecursion 16
MaxFiles 10000
ScanPE yes
ScanELF yes
ScanOLE2 yes
ScanPDF yes
ScanSWF yes
ScanHTML yes
ScanMail yes
ScanArchive yes
`, socketPath)

	if err := os.WriteFile(confPath, []byte(conf), 0644); err != nil {
		return fmt.Errorf("write clamd.conf: %w", err)
	}
	log.Printf("[Antivirus] Created clamd.conf at %s", confPath)
	return nil
}

func EnsureFreshclam() {
	freshclamConf := filepath.Dir(DefaultConfPath()) + "/freshclam.conf"
	if _, err := os.Stat(freshclamConf); err != nil {
		conf := `DatabaseMirror database.clamav.net
NotifyClamd ` + DefaultConfPath() + "\n"
		os.WriteFile(freshclamConf, []byte(conf), 0644)
	}

	log.Printf("[Antivirus] Updating virus definitions...")
	cmd := exec.Command("freshclam", "--quiet")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Printf("[Antivirus] ⚠️  freshclam update failed (may need to run manually): %v", err)
	}
}

func StartClamd() error {
	log.Printf("[Antivirus] Starting clamd...")
	cmd := exec.Command("clamd")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start clamd: %w", err)
	}
	go cmd.Wait()
	log.Printf("[Antivirus] clamd started (PID %d)", cmd.Process.Pid)
	return nil
}
