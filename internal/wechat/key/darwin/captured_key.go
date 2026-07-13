package darwin

// CapturedDBKey is one PBKDF2 password observation captured while WeChat opens
// an encrypted database. Salt identifies the database that triggered it; Key is
// the 32-byte SQLCipher passphrase encoded as lowercase hex.
type CapturedDBKey struct {
	Key        string
	DerivedKey string
	Salt       string
	Rounds     int
	Len        int
	DerivedLen int
	PRF        int
	Algorithm  int
}
