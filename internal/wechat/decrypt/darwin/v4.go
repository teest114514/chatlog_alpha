package darwin

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"io"
	"os"

	"github.com/sjzar/chatlog/internal/errors"
	"github.com/sjzar/chatlog/internal/wechat/decrypt/common"
	"golang.org/x/crypto/pbkdf2"
)

const (
	PageSize     = 4096
	ReserveSize  = 80 // IV(16) + HMAC-SHA512(64)
	SaltSize     = 16
	AESBlockSize = 16
	IVSize       = 16
	HMACSize     = 64
	// WeChat 4.x / SQLCipher 4 defaults
	KDFIter    = 256000
	MacKDFIter = 2
)

type V4Decryptor struct{}

func NewV4Decryptor() *V4Decryptor {
	return &V4Decryptor{}
}

func (d *V4Decryptor) Decrypt(ctx context.Context, dbfile string, hexKey string, output io.Writer) error {
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return errors.DecodeKeyFailed(err)
	}
	if len(key) != common.KeySize {
		return errors.ErrKeyLengthMust32
	}

	dbFile, err := os.Open(dbfile)
	if err != nil {
		return errors.OpenFileFailed(dbfile, err)
	}
	defer dbFile.Close()

	fileInfo, err := dbFile.Stat()
	if err != nil {
		return errors.StatFileFailed(dbfile, err)
	}
	totalPages := int((fileInfo.Size() + PageSize - 1) / PageSize)
	if totalPages <= 0 {
		return errors.ErrDecryptIncorrectKey
	}

	// Salt lives in page 1; derive once then reuse for all pages.
	first := make([]byte, PageSize)
	if _, err := io.ReadFull(dbFile, first); err != nil {
		return errors.ReadFileFailed(dbfile, err)
	}
	salt := first[:SaltSize]
	encKey, _, err := d.DeriveKeys(key, salt)
	if err != nil {
		return err
	}
	if !d.Validate(first, key) {
		return errors.ErrDecryptIncorrectKey
	}

	if _, err := dbFile.Seek(0, io.SeekStart); err != nil {
		return errors.ReadFileFailed(dbfile, err)
	}

	page := make([]byte, PageSize)
	for pg := 0; pg < totalPages; pg++ {
		select {
		case <-ctx.Done():
			return errors.ErrDecryptOperationCanceled
		default:
		}

		n, readErr := io.ReadFull(dbFile, page)
		if readErr != nil {
			if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
				if n == 0 {
					break
				}
				for i := n; i < PageSize; i++ {
					page[i] = 0
				}
			} else {
				return errors.ReadFileFailed(dbfile, readErr)
			}
		}

		dec, err := decryptPage(page, encKey, pg+1)
		if err != nil {
			return err
		}
		if _, err := output.Write(dec); err != nil {
			return errors.WriteOutputFailed(err)
		}
	}

	return nil
}

// Validate checks that password derives a usable SQLCipher page-1 key.
// WeChat 4.x stores a 32-byte passphrase; real enc_key = PBKDF2-HMAC-SHA512(pass, salt, 256000).
// Page-1 HMAC is unreliable across builds, so we verify decrypted SQLite header fields.
func (d *V4Decryptor) Validate(page1 []byte, key []byte) bool {
	if len(page1) < PageSize || len(key) != common.KeySize {
		return false
	}
	if string(page1[:15]) == "SQLite format 3" {
		return false // already plaintext / not encrypted
	}
	salt := page1[:SaltSize]
	encKey, _, err := d.DeriveKeys(key, salt)
	if err != nil {
		return false
	}
	dec, err := decryptPage(page1[:PageSize], encKey, 1)
	if err != nil || len(dec) < 100 {
		return false
	}
	if string(dec[:len(common.SQLiteHeader)]) != common.SQLiteHeader {
		return false
	}
	pageSz := binary.BigEndian.Uint16(dec[16:18])
	if pageSz != PageSize && pageSz != 1 { // 1 means 65536 in SQLite
		return false
	}
	writeVer, readVer := dec[18], dec[19]
	if writeVer > 2 || readVer > 2 || writeVer == 0 || readVer == 0 {
		return false
	}
	if dec[21] != 64 || dec[22] != 32 || dec[23] != 32 {
		return false
	}
	// reserved space should match SQLCipher reserve (IV+HMAC)
	if dec[20] != byte(ReserveSize) && dec[20] != 0 {
		// WeChat writes reserve=80; accept 0 only if other fields look sane.
		if pageSz != PageSize {
			return false
		}
	}
	textEnc := binary.BigEndian.Uint32(dec[56:60])
	if textEnc == 0 {
		// SQLite leaves the encoding and schema-format fields at zero until
		// the first schema object is created. WeChat ships several valid
		// one-page databases in exactly this initialized-but-empty state (for
		// example weclaw.db and solitaire.db). Keep the remaining checks strict
		// so a wrong key cannot pass merely because encoding happens to be zero.
		if binary.BigEndian.Uint32(dec[44:48]) != 0 ||
			len(dec) < 108 || dec[100] != 13 ||
			binary.BigEndian.Uint16(dec[103:105]) != 0 {
			return false
		}
	} else if textEnc != 1 && textEnc != 2 && textEnc != 3 {
		return false
	}
	return true
}

func (d *V4Decryptor) GetPageSize() int {
	return PageSize
}

func (d *V4Decryptor) GetReserve() int {
	return ReserveSize
}

func (d *V4Decryptor) GetHMACSize() int {
	return HMACSize
}

func (d *V4Decryptor) GetHashFunc() func() hash.Hash {
	return sha512.New
}

// DeriveKeys derives SQLCipher 4 enc_key and mac_key from the 32-byte passphrase.
func (d *V4Decryptor) DeriveKeys(key []byte, salt []byte) ([]byte, []byte, error) {
	if len(key) != common.KeySize {
		return nil, nil, errors.ErrKeyLengthMust32
	}
	if len(salt) < SaltSize {
		return nil, nil, errors.ErrDecryptIncorrectKey
	}
	salt = salt[:SaltSize]
	encKey := pbkdf2.Key(key, salt, KDFIter, common.KeySize, sha512.New)
	macSalt := common.XorBytes(salt, 0x3a)
	macKey := pbkdf2.Key(encKey, macSalt, MacKDFIter, common.KeySize, sha512.New)
	return encKey, macKey, nil
}

func (d *V4Decryptor) GetVersion() string {
	return "Darwin v4 (SQLCipher4 PBKDF2-HMAC-SHA512)"
}

func decryptPage(pageData []byte, encKey []byte, pgno int) ([]byte, error) {
	if len(pageData) < PageSize || len(encKey) != common.KeySize {
		return nil, errors.ErrDecryptIncorrectKey
	}
	ivOffset := PageSize - ReserveSize
	iv := pageData[ivOffset : ivOffset+IVSize]

	result := make([]byte, PageSize)

	if pgno == 1 {
		enc := pageData[SaltSize : PageSize-ReserveSize]
		dec, err := aesCBCDecrypt(encKey, iv, enc)
		if err != nil {
			return nil, err
		}
		copy(result[:16], []byte(common.SQLiteHeader))
		copy(result[16:PageSize-ReserveSize], dec)
		return result, nil
	}

	enc := pageData[:PageSize-ReserveSize]
	dec, err := aesCBCDecrypt(encKey, iv, enc)
	if err != nil {
		return nil, err
	}
	copy(result[:PageSize-ReserveSize], dec)
	return result, nil
}

func aesCBCDecrypt(key []byte, iv []byte, data []byte) ([]byte, error) {
	if len(data) == 0 || len(data)%AESBlockSize != 0 {
		return nil, errors.ErrDecryptIncorrectKey
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.DecryptCreateCipherFailed(err)
	}
	out := make([]byte, len(data))
	copy(out, data)
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(out, out)
	return out, nil
}

// PageHMAC computes SQLCipher HMAC for debugging/tests (page_no is 1-based).
func PageHMAC(macKey, page []byte, pageNo uint32) []byte {
	dataEnd := PageSize - ReserveSize + IVSize
	mac := hmac.New(sha512.New, macKey)
	mac.Write(page[:dataEnd])
	var pn [4]byte
	binary.LittleEndian.PutUint32(pn[:], pageNo)
	mac.Write(pn[:])
	return mac.Sum(nil)
}
