// Utility functions for Spectrum Chain
package utils

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"golang.org/x/crypto/ripemd160"
)

// GenerateRandomID generates a random ID string
func GenerateRandomID() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		// In case of error, use timestamp as fallback
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// GeneratePrivateKey generates a new ECDSA private key
func GeneratePrivateKey() ([]byte, error) {
	privateKey, err := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	privateKeyBytes := privateKey.D.Bytes()
	return privateKeyBytes, nil
}

// PrivateKeyToPublicKey converts a private key to a public key
func PrivateKeyToPublicKey(privateKey []byte) ([]byte, error) {
	// Parse private key
	key := new(big.Int).SetBytes(privateKey)
	curve := btcec.S256()

	// Generate public key
	x, y := curve.ScalarBaseMult(key.Bytes())

	// Serialize public key
	publicKey := append(x.Bytes(), y.Bytes()...)
	return publicKey, nil
}

// Sign signs data with a private key
func Sign(data []byte, privateKey []byte) ([]byte, error) {
	// Parse private key
	key := new(big.Int).SetBytes(privateKey)
	curve := btcec.S256()

	// Create private key object
	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = curve
	priv.D = key
	priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(key.Bytes())

	// Hash data
	hash := sha256.Sum256(data)

	// Sign data
	r, s, err := ecdsa.Sign(rand.Reader, priv, hash[:])
	if err != nil {
		return nil, err
	}

	// Serialize signature
	signature := append(r.Bytes(), s.Bytes()...)
	return signature, nil
}

// Verify verifies a signature
func Verify(data []byte, signature []byte, publicKey []byte) bool {
	// Parse public key
	curve := btcec.S256()
	x := new(big.Int).SetBytes(publicKey[:len(publicKey)/2])
	y := new(big.Int).SetBytes(publicKey[len(publicKey)/2:])

	// Create public key object
	pub := new(ecdsa.PublicKey)
	pub.Curve = curve
	pub.X = x
	pub.Y = y

	// Hash data
	hash := sha256.Sum256(data)

	// Parse signature
	r := new(big.Int).SetBytes(signature[:len(signature)/2])
	s := new(big.Int).SetBytes(signature[len(signature)/2:])

	// Verify signature
	return ecdsa.Verify(pub, hash[:], r, s)
}

// HashPubKey hashes a public key
func HashPubKey(pubKey []byte) []byte {
	// SHA-256 hash
	sha256Hash := sha256.Sum256(pubKey)

	// RIPEMD-160 hash
	ripemd160Hasher := ripemd160.New()
	_, err := ripemd160Hasher.Write(sha256Hash[:])
	if err != nil {
		return nil
	}

	return ripemd160Hasher.Sum(nil)
}

// FileExists checks if a file exists
func FileExists(filePath string) bool {
	info, err := os.Stat(filePath)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

// DirExists checks if a directory exists
func DirExists(dirPath string) bool {
	info, err := os.Stat(dirPath)
	if err != nil {
		return false
	}
	return info.IsDir()
}

// CreateDirIfNotExists creates a directory if it doesn't exist
func CreateDirIfNotExists(dirPath string) error {
	if !DirExists(dirPath) {
		return os.MkdirAll(dirPath, 0755)
	}
	return nil
}

// CopyFile copies a file
func CopyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	if err != nil {
		return err
	}

	return dstFile.Sync()
}

// BytesToHex converts bytes to a hex string
func BytesToHex(bytes []byte) string {
	return hex.EncodeToString(bytes)
}

// HexToBytes converts a hex string to bytes
func HexToBytes(hexStr string) ([]byte, error) {
	return hex.DecodeString(hexStr)
}

// TruncateString truncates a string to the specified length
func TruncateString(str string, length int) string {
	if len(str) <= length {
		return str
	}
	return str[:length] + "..."
}

// ValidateAddress validates an address
func ValidateAddress(address string) bool {
	// For simplicity, just check if it's a valid hex string
	_, err := hex.DecodeString(address)
	return err == nil && len(address) == 40 // 20 bytes in hex
}

// SplitAndTrim splits a string and trims spaces
func SplitAndTrim(s, sep string) []string {
	if s == "" {
		return []string{}
	}

	parts := strings.Split(s, sep)
	result := make([]string, 0, len(parts))

	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}

	return result
}

// FormatDuration formats a duration in seconds
func FormatDuration(seconds int64) string {
	d := time.Duration(seconds) * time.Second

	days := int(d.Hours() / 24)
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	secs := int(d.Seconds()) % 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm %ds", days, hours, minutes, secs)
	} else if hours > 0 {
		return fmt.Sprintf("%dh %dm %ds", hours, minutes, secs)
	} else if minutes > 0 {
		return fmt.Sprintf("%dm %ds", minutes, secs)
	}

	return fmt.Sprintf("%ds", secs)
}

// FormatSize formats a size in bytes
func FormatSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}

	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// ParseDuration parses a duration string
func ParseDuration(s string) (time.Duration, error) {
	return time.ParseDuration(s)
}

// ParseSize parses a size string
func ParseSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	s = strings.ToUpper(s)

	var multiplier int64 = 1

	if strings.HasSuffix(s, "KB") {
		multiplier = 1024
		s = s[:len(s)-2]
	} else if strings.HasSuffix(s, "K") {
		multiplier = 1024
		s = s[:len(s)-1]
	} else if strings.HasSuffix(s, "MB") {
		multiplier = 1024 * 1024
		s = s[:len(s)-2]
	} else if strings.HasSuffix(s, "M") {
		multiplier = 1024 * 1024
		s = s[:len(s)-1]
	} else if strings.HasSuffix(s, "GB") {
		multiplier = 1024 * 1024 * 1024
		s = s[:len(s)-2]
	} else if strings.HasSuffix(s, "G") {
		multiplier = 1024 * 1024 * 1024
		s = s[:len(s)-1]
	} else if strings.HasSuffix(s, "TB") {
		multiplier = 1024 * 1024 * 1024 * 1024
		s = s[:len(s)-2]
	} else if strings.HasSuffix(s, "T") {
		multiplier = 1024 * 1024 * 1024 * 1024
		s = s[:len(s)-1]
	} else if strings.HasSuffix(s, "B") {
		s = s[:len(s)-1]
	}

	value, err := ParseInt64(s)
	if err != nil {
		return 0, err
	}

	return value * multiplier, nil
}

// ParseInt64 parses an int64 from a string
// ParseInt64 parses an int64 from a string
func ParseInt64(s string) (int64, error) {
	s = strings.TrimSpace(s)
	bigInt, success := new(big.Int).SetString(s, 10)
	if !success {
		return 0, fmt.Errorf("failed to parse integer from string: %s", s)
	}
	// Check if the value fits in an int64
	if !bigInt.IsInt64() {
		return 0, fmt.Errorf("value too large for int64: %s", s)
	}
	return bigInt.Int64(), nil
}

// TimeTrack is used for performance tracking
func TimeTrack(start time.Time, name string) {
	elapsed := time.Since(start)
	fmt.Printf("%s took %s\n", name, elapsed)
}
