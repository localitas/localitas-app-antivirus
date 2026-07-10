package antivirus

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const chunkSize = 2048

type Scanner struct {
	socketPath string
}

func NewScanner(socketPath string) *Scanner {
	return &Scanner{socketPath: socketPath}
}

func (s *Scanner) Ping() (string, error) {
	conn, err := net.DialTimeout("unix", s.socketPath, 5*time.Second)
	if err != nil {
		return "", fmt.Errorf("clamd not reachable: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write([]byte("zPING\x00")); err != nil {
		return "", err
	}

	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(buf[:n]), "\x00\n"), nil
}

func (s *Scanner) Version() (string, error) {
	conn, err := net.DialTimeout("unix", s.socketPath, 5*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write([]byte("zVERSION\x00")); err != nil {
		return "", err
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(buf[:n]), "\x00\n"), nil
}

func (s *Scanner) ScanPath(filePath string) (clean bool, threatName string, err error) {
	conn, err := net.DialTimeout("unix", s.socketPath, 10*time.Second)
	if err != nil {
		return false, "", fmt.Errorf("clamd not reachable: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Minute))

	cmd := fmt.Sprintf("zSCAN %s\x00", filePath)
	if _, err := conn.Write([]byte(cmd)); err != nil {
		return false, "", fmt.Errorf("send SCAN: %w", err)
	}

	resp := make([]byte, 1024)
	n, readErr := conn.Read(resp)
	if readErr != nil {
		return false, "", fmt.Errorf("read response: %w", readErr)
	}
	response := strings.TrimRight(string(resp[:n]), "\x00\n")

	if strings.HasSuffix(response, "OK") {
		return true, "", nil
	}
	if strings.Contains(response, "FOUND") {
		parts := strings.SplitN(response, ":", 2)
		if len(parts) == 2 {
			threat := strings.TrimSpace(parts[1])
			threat = strings.TrimSuffix(threat, " FOUND")
			return false, strings.TrimSpace(threat), nil
		}
		return false, "unknown", nil
	}
	return false, "", fmt.Errorf("unexpected clamd response: %s", response)
}

func (s *Scanner) ScanStream(reader io.Reader) (clean bool, threatName string, err error) {
	conn, err := net.DialTimeout("unix", s.socketPath, 10*time.Second)
	if err != nil {
		return false, "", fmt.Errorf("clamd not reachable: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Minute))

	if _, err := conn.Write([]byte("zINSTREAM\x00")); err != nil {
		return false, "", fmt.Errorf("send INSTREAM: %w", err)
	}

	buf := make([]byte, chunkSize)
	for {
		n, readErr := reader.Read(buf)
		if n > 0 {
			sizeBytes := make([]byte, 4)
			binary.BigEndian.PutUint32(sizeBytes, uint32(n))
			if _, err := conn.Write(sizeBytes); err != nil {
				return false, "", fmt.Errorf("write chunk size: %w", err)
			}
			if _, err := conn.Write(buf[:n]); err != nil {
				return false, "", fmt.Errorf("write chunk data: %w", err)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return false, "", fmt.Errorf("read file: %w", readErr)
		}
	}

	terminator := make([]byte, 4)
	binary.BigEndian.PutUint32(terminator, 0)
	if _, err := conn.Write(terminator); err != nil {
		return false, "", fmt.Errorf("write terminator: %w", err)
	}

	resp := make([]byte, 1024)
	n, err := conn.Read(resp)
	if err != nil {
		return false, "", fmt.Errorf("read response: %w", err)
	}
	response := strings.TrimRight(string(resp[:n]), "\x00\n")

	if strings.HasSuffix(response, "OK") {
		return true, "", nil
	}

	if strings.Contains(response, "FOUND") {
		parts := strings.SplitN(response, ":", 2)
		if len(parts) == 2 {
			threat := strings.TrimSpace(parts[1])
			threat = strings.TrimSuffix(threat, " FOUND")
			return false, strings.TrimSpace(threat), nil
		}
		return false, "unknown", nil
	}

	return false, "", fmt.Errorf("unexpected clamd response: %s", response)
}
