package darwin

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"hash"
	"io"
	"os"

	"github.com/sjzar/chatlog/internal/errors"
	"github.com/sjzar/chatlog/internal/wechat/decrypt/common"
)

const (
	PageSize     = 4096
	ReserveSize  = 80 // IV(16) + HMAC(64)
	SaltSize     = 16
	AESBlockSize = 16
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

		dec, err := decryptPage(page, key, pg+1)
		if err != nil {
			return err
		}
		if _, err := output.Write(dec); err != nil {
			return errors.WriteOutputFailed(err)
		}
	}

	return nil
}

func (d *V4Decryptor) Validate(page1 []byte, key []byte) bool {
	if len(page1) < PageSize || len(key) != common.KeySize {
		return false
	}
	dec, err := decryptPage(page1[:PageSize], key, 1)
	if err != nil || len(dec) < len(common.SQLiteHeader) {
		return false
	}
	return string(dec[:len(common.SQLiteHeader)]) == common.SQLiteHeader
}

func (d *V4Decryptor) GetPageSize() int {
	return PageSize
}

func (d *V4Decryptor) GetReserve() int {
	return ReserveSize
}

func (d *V4Decryptor) GetHMACSize() int {
	return 64
}

func (d *V4Decryptor) GetHashFunc() func() hash.Hash {
	return nil
}

func (d *V4Decryptor) DeriveKeys(key []byte, salt []byte) ([]byte, []byte, error) {
	_ = salt
	if len(key) != common.KeySize {
		return nil, nil, errors.ErrKeyLengthMust32
	}
	enc := make([]byte, len(key))
	copy(enc, key)
	return enc, nil, nil
}

func (d *V4Decryptor) GetVersion() string {
	return "Darwin v4 (wx-cli compatible)"
}

func decryptPage(pageData []byte, key []byte, pgno int) ([]byte, error) {
	if len(pageData) < PageSize || len(key) != common.KeySize {
		return nil, errors.ErrDecryptIncorrectKey
	}
	ivOffset := PageSize - ReserveSize
	iv := pageData[ivOffset : ivOffset+16]

	result := make([]byte, PageSize)

	if pgno == 1 {
		enc := pageData[SaltSize : PageSize-ReserveSize]
		dec, err := aesCBCDecrypt(key, iv, enc)
		if err != nil {
			return nil, err
		}
		copy(result[:16], []byte(common.SQLiteHeader))
		copy(result[16:PageSize-ReserveSize], dec)
		return result, nil
	}

	enc := pageData[:PageSize-ReserveSize]
	dec, err := aesCBCDecrypt(key, iv, enc)
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
