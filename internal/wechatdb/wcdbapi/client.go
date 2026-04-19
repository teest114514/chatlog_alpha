package wcdbapi

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	_ "github.com/mattn/go-sqlite3"
	"github.com/sjzar/chatlog/internal/wechat/decrypt"
)

type cacheEntry struct {
	srcMTime int64
	walMTime int64
	keyHex   string
	outPath  string
}

// Client is a built-in wcdb_api compatible query client.
// It provides the core open/query methods in-process (no external dylib).
type Client struct {
	dataDir  string
	dataKey  string
	cacheDir string
	allKeys  map[string]string // normalized rel db path -> enc key

	mu    sync.Mutex
	cache map[string]cacheEntry // rel db path -> decrypted cache entry
}

func (c *Client) DataDir() string { return c.dataDir }

func NewClient(dataDir, dataKey string) (*Client, error) {
	dataDir = strings.TrimSpace(dataDir)
	dataKey = strings.TrimSpace(dataKey)
	if dataDir == "" {
		return nil, fmt.Errorf("data dir is empty")
	}
	if dataKey != "" && len(dataKey) != 64 {
		return nil, fmt.Errorf("invalid data key length: %d", len(dataKey))
	}
	normalizedDir, err := normalizeDataDir(dataDir)
	if err != nil {
		return nil, err
	}
	cacheDir, err := resolveCacheDir()
	if err != nil {
		return nil, err
	}
	allKeys := loadAllKeysMap(normalizedDir)
	return &Client{
		dataDir:  normalizedDir,
		dataKey:  dataKey,
		cacheDir: cacheDir,
		allKeys:  allKeys,
		cache:    make(map[string]cacheEntry),
	}, nil
}

func normalizeDataDir(dataDir string) (string, error) {
	clean := filepath.Clean(dataDir)
	abs, err := filepath.Abs(clean)
	if err == nil {
		clean = abs
	}
	if base := strings.ToLower(filepath.Base(clean)); base == "db_storage" {
		if isDir(clean) {
			return clean, nil
		}
		return "", fmt.Errorf("db_storage dir not found: %s", clean)
	}

	// account root form: .../xwechat_files/wxid_xxx
	dbStorage := filepath.Join(clean, "db_storage")
	if isDir(dbStorage) {
		return dbStorage, nil
	}
	// already db root form (contains session/contact/message dirs)
	if hasAnyDir(clean, []string{"session", "contact", "message", "media", "sns"}) {
		return clean, nil
	}
	return "", fmt.Errorf("invalid data dir: %s (need db_storage or account root containing db_storage)", clean)
}

func resolveCacheDir() (string, error) {
	candidates := make([]string, 0, 2)
	if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
		candidates = append(candidates, filepath.Join(home, ".chatlog", "wcdb_cache"))
	}
	candidates = append(candidates, filepath.Join(os.TempDir(), "chatlog_wcdb_cache"))

	var lastErr error
	for _, dir := range candidates {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			lastErr = err
			continue
		}
		probe := filepath.Join(dir, ".write_test")
		if err := os.WriteFile(probe, []byte("ok"), 0o644); err != nil {
			lastErr = err
			continue
		}
		_ = os.Remove(probe)
		return dir, nil
	}
	if lastErr != nil {
		return "", fmt.Errorf("failed to init wcdb cache dir: %w", lastErr)
	}
	return "", fmt.Errorf("failed to init wcdb cache dir")
}

func isDir(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.IsDir()
}

func hasAnyDir(base string, names []string) bool {
	for _, n := range names {
		st, err := os.Stat(filepath.Join(base, n))
		if err == nil && st.IsDir() {
			return true
		}
	}
	return false
}

func (c *Client) OpenAccount(path, key string) error {
	if strings.TrimSpace(path) == "" || strings.TrimSpace(key) == "" {
		return fmt.Errorf("invalid open_account arguments")
	}
	return nil
}

func (c *Client) ListMessageDBs() ([]string, error) {
	msgDir := filepath.Join(c.dataDir, "message")
	entries, err := os.ReadDir(msgDir)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(entries))
	re := regexp.MustCompile(`^message_([0-9]?[0-9])?\.db$`)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if re.MatchString(strings.ToLower(e.Name())) {
			p := filepath.Join(msgDir, e.Name())
			if c.CanQueryDB(p) {
				out = append(out, p)
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

func (c *Client) ListMediaDBs() ([]string, error) {
	out := make([]string, 0, 8)
	// Prefer current WeChat v4 layout: db_storage/hardlink/hardlink.db.
	for _, p := range []string{
		filepath.Join(c.dataDir, "hardlink", "hardlink.db"),
		filepath.Join(c.dataDir, "media", "hardlink.db"), // backward-compatible fallback
	} {
		if _, err := os.Stat(p); err == nil {
			out = append(out, p)
		}
	}

	re := regexp.MustCompile(`^media_([0-9]?[0-9])?\.db$`)
	for _, dir := range []string{
		filepath.Join(c.dataDir, "message"),
		filepath.Join(c.dataDir, "media"), // backward-compatible fallback
	} {
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if re.MatchString(strings.ToLower(e.Name())) {
				p := filepath.Join(dir, e.Name())
				if c.CanQueryDB(p) {
					out = append(out, p)
				}
			}
		}
	}

	uniq := make([]string, 0, len(out))
	seen := map[string]struct{}{}
	for _, p := range out {
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		uniq = append(uniq, p)
	}
	return uniq, nil
}

func (c *Client) Query(kind, path, query string) ([]map[string]interface{}, error) {
	dbPath, err := c.resolveDBPath(kind, path)
	if err != nil {
		return nil, err
	}
	decPath, err := c.ensureDecrypted(dbPath)
	if err != nil {
		return nil, err
	}
	return queryRows(decPath, query)
}

func (c *Client) CanQueryDB(dbPath string) bool {
	p := strings.TrimSpace(dbPath)
	if p == "" {
		return false
	}
	if _, err := os.Stat(p); err != nil {
		return false
	}
	if ok, err := isReadableSQLite(p); err == nil && ok {
		return true
	}
	_, err := c.resolveDataKey(p)
	return err == nil
}

func (c *Client) ListAllKeyDBs() []string {
	if len(c.allKeys) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(c.allKeys))
	out := make([]string, 0, len(c.allKeys))
	for rel := range c.allKeys {
		p := strings.TrimSpace(rel)
		if p == "" {
			continue
		}
		var abs string
		if filepath.IsAbs(p) {
			abs = filepath.Clean(p)
		} else {
			relPath := strings.TrimPrefix(strings.ReplaceAll(filepath.ToSlash(p), "\\", "/"), "db_storage/")
			abs = filepath.Join(c.dataDir, filepath.FromSlash(relPath))
		}
		if _, err := os.Stat(abs); err != nil {
			continue
		}
		if _, ok := seen[abs]; ok {
			continue
		}
		seen[abs] = struct{}{}
		out = append(out, abs)
	}
	sort.Strings(out)
	return out
}

func (c *Client) GetSessions() ([]map[string]interface{}, error) {
	sql := `
SELECT username, summary, last_timestamp, last_msg_sender, last_sender_display_name, last_msg_type, last_msg_sub_type
FROM SessionTable
WHERE last_timestamp > 0
ORDER BY last_timestamp DESC
`
	return c.Query("session", "", sql)
}

func (c *Client) GetMessages(username string, limit, offset int) ([]map[string]interface{}, error) {
	return c.GetMessagesInRange(username, 0, 0, limit, offset)
}

func (c *Client) GetMessagesInRange(username string, since, until int64, limit, offset int) ([]map[string]interface{}, error) {
	if username == "" {
		return nil, fmt.Errorf("username is empty")
	}
	_talkerMd5Bytes := md5.Sum([]byte(username))
	talkerMd5 := hex.EncodeToString(_talkerMd5Bytes[:])
	tableName := "Msg_" + talkerMd5

	msgDBs, err := c.ListMessageDBs()
	if err != nil {
		return nil, err
	}
	if len(msgDBs) == 0 {
		return nil, fmt.Errorf("message db not found")
	}

	type dbCandidate struct {
		decPath string
		maxTS   int64
	}
	candidates := make([]dbCandidate, 0, len(msgDBs))
	for _, dbPath := range msgDBs {
		decPath, err := c.ensureDecrypted(dbPath)
		if err != nil {
			continue
		}
		exists, err := tableExists(decPath, tableName)
		if err != nil {
			continue
		}
		if !exists {
			continue
		}
		maxTS, err := tableMaxCreateTime(decPath, tableName)
		if err != nil {
			continue
		}
		candidates = append(candidates, dbCandidate{decPath: decPath, maxTS: maxTS})
	}
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].maxTS > candidates[j].maxTS
	})

	perDBLimit := 0
	if limit > 0 {
		perDBLimit = limit + offset
	}
	if perDBLimit <= 0 {
		perDBLimit = 5000
	}
	if perDBLimit > 50000 {
		perDBLimit = 50000
	}

	var out []map[string]interface{}
	for _, item := range candidates {
		var where []string
		if since > 0 {
			where = append(where, fmt.Sprintf("m.create_time >= %d", since))
		}
		if until > 0 {
			where = append(where, fmt.Sprintf("m.create_time <= %d", until))
		}
		whereSQL := ""
		if len(where) > 0 {
			whereSQL = "WHERE " + strings.Join(where, " AND ")
		}

		sql := fmt.Sprintf(`
SELECT m.local_id, m.sort_seq, m.server_id, m.local_type, n.user_name, m.create_time, m.message_content, m.packed_info_data, m.status
FROM [%s] m
LEFT JOIN Name2Id n ON m.real_sender_id = n.rowid
%s
ORDER BY m.create_time DESC
LIMIT %d OFFSET 0
`, tableName, whereSQL, perDBLimit)
		rows, err := queryRows(item.decPath, sql)
		if err != nil {
			continue
		}
		out = append(out, rows...)
	}

	sort.Slice(out, func(i, j int) bool {
		ti := toInt64(out[i]["create_time"])
		tj := toInt64(out[j]["create_time"])
		if ti == tj {
			return toInt64(out[i]["sort_seq"]) > toInt64(out[j]["sort_seq"])
		}
		return ti > tj
	})

	if offset > 0 {
		if offset >= len(out) {
			return []map[string]interface{}{}, nil
		}
		out = out[offset:]
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	sort.Slice(out, func(i, j int) bool {
		ti := toInt64(out[i]["create_time"])
		tj := toInt64(out[j]["create_time"])
		if ti == tj {
			return toInt64(out[i]["sort_seq"]) < toInt64(out[j]["sort_seq"])
		}
		return ti < tj
	})
	return out, nil
}

func tableExists(dbPath, tableName string) (bool, error) {
	rows, err := queryRows(dbPath, fmt.Sprintf(
		"SELECT 1 AS ok FROM sqlite_master WHERE type='table' AND name='%s' LIMIT 1",
		strings.ReplaceAll(tableName, "'", "''"),
	))
	if err != nil {
		return false, err
	}
	return len(rows) > 0, nil
}

func tableMaxCreateTime(dbPath, tableName string) (int64, error) {
	rows, err := queryRows(dbPath, fmt.Sprintf("SELECT MAX(create_time) AS max_ts FROM [%s]", tableName))
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, nil
	}
	return toInt64(rows[0]["max_ts"]), nil
}

func (c *Client) resolveDBPath(kind, path string) (string, error) {
	if strings.TrimSpace(path) != "" {
		p := strings.TrimSpace(path)
		if !filepath.IsAbs(p) {
			p = strings.TrimPrefix(strings.ReplaceAll(filepath.Clean(p), "\\", "/"), "db_storage/")
			p = filepath.Join(c.dataDir, p)
		}
		return p, nil
	}
	switch strings.ToLower(kind) {
	case "session":
		return filepath.Join(c.dataDir, "session", "session.db"), nil
	case "contact", "chatroom":
		return filepath.Join(c.dataDir, "contact", "contact.db"), nil
	case "sns":
		return filepath.Join(c.dataDir, "sns", "sns.db"), nil
	case "media", "voice":
		if strings.ToLower(kind) == "voice" {
			re := regexp.MustCompile(`^media_([0-9]?[0-9])?\.db$`)
			for _, dir := range []string{
				filepath.Join(c.dataDir, "message"),
				filepath.Join(c.dataDir, "media"), // backward-compatible fallback
			} {
				entries, _ := os.ReadDir(dir)
				for _, e := range entries {
					if e.IsDir() {
						continue
					}
					if re.MatchString(strings.ToLower(e.Name())) {
						p := filepath.Join(dir, e.Name())
						if _, err := os.Stat(p); err == nil {
							return p, nil
						}
					}
				}
			}
			return "", fmt.Errorf("voice db not found")
		}
		// media(hardlink) database
		for _, p := range []string{
			filepath.Join(c.dataDir, "hardlink", "hardlink.db"),
			filepath.Join(c.dataDir, "media", "hardlink.db"), // backward-compatible fallback
		} {
			if _, err := os.Stat(p); err == nil {
				return p, nil
			}
		}
		return "", fmt.Errorf("hardlink db not found")
	default:
		return "", fmt.Errorf("unsupported db kind: %s", kind)
	}
}

func (c *Client) ensureDecrypted(src string) (string, error) {
	st, err := os.Stat(src)
	if err != nil {
		return "", err
	}
	if plain, err := isReadableSQLite(src); err == nil && plain {
		return src, nil
	}
	src = filepath.Clean(src)
	rel, err := filepath.Rel(c.dataDir, src)
	if err != nil {
		rel = filepath.Base(src)
	}
	rel = normalizeKeyPath(rel)
	useKey, err := c.resolveDataKey(src)
	if err != nil {
		return "", err
	}
	walPath := src + "-wal"
	walMTime := fileMTimeNS(walPath)

	c.mu.Lock()
	entry, ok := c.cache[rel]
	c.mu.Unlock()

	srcMTime := st.ModTime().UnixNano()
	if ok && entry.srcMTime == srcMTime && entry.walMTime == walMTime && entry.keyHex == useKey {
		if _, err := os.Stat(entry.outPath); err == nil {
			return entry.outPath, nil
		}
	}

	// decrypt to temp cache file
	hexID := fmt.Sprintf("%x", md5.Sum([]byte(rel)))
	outPath := filepath.Join(c.cacheDir, hexID+".db")
	tmpPath := outPath + ".tmp"

	f, err := os.Create(tmpPath)
	if err != nil {
		return "", err
	}
	decryptor, err := decrypt.NewDecryptor("darwin", 4)
	if err != nil {
		f.Close()
		_ = os.Remove(tmpPath)
		return "", err
	}
	if err := decryptor.Decrypt(context.Background(), src, useKey, f); err != nil {
		f.Close()
		_ = os.Remove(tmpPath)
		return "", err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return "", err
	}
	if walMTime > 0 {
		keyBytes, err := decodeHexKey(useKey)
		if err != nil {
			_ = os.Remove(tmpPath)
			return "", err
		}
		if err := applyWAL(walPath, tmpPath, keyBytes); err != nil {
			_ = os.Remove(tmpPath)
			return "", err
		}
	}
	if err := os.Rename(tmpPath, outPath); err != nil {
		_ = os.Remove(tmpPath)
		return "", err
	}

	c.mu.Lock()
	c.cache[rel] = cacheEntry{srcMTime: srcMTime, walMTime: walMTime, keyHex: useKey, outPath: outPath}
	c.mu.Unlock()
	return outPath, nil
}

func (c *Client) resolveDataKey(src string) (string, error) {
	if len(c.allKeys) == 0 {
		return "", fmt.Errorf("all_keys.json not found for encrypted db: %s", src)
	}
	if rel, ok := relPathFromDataDir(c.dataDir, src); ok {
		candidates := []string{
			normalizeKeyPath(rel),
			normalizeKeyPath(strings.TrimPrefix(rel, "db_storage/")),
		}
		for _, p := range candidates {
			if key, ok := c.allKeys[p]; ok && len(key) == 64 {
				return key, nil
			}
		}
	}
	return "", fmt.Errorf("all_keys.json missing key for db: %s", src)
}

func loadAllKeysMap(dataDir string) map[string]string {
	paths := []string{
		filepath.Join(dataDir, "all_keys.json"),
	}
	if strings.EqualFold(filepath.Base(filepath.Clean(dataDir)), "db_storage") {
		paths = append([]string{filepath.Join(filepath.Dir(filepath.Clean(dataDir)), "all_keys.json")}, paths...)
	}
	var raw []byte
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err == nil {
			raw = b
			break
		}
	}
	if len(raw) == 0 {
		return nil
	}
	obj := map[string]any{}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil
	}
	out := make(map[string]string, len(obj))
	for k, v := range obj {
		key := ""
		switch t := v.(type) {
		case string:
			key = t
		case map[string]any:
			if vv, ok := t["enc_key"].(string); ok {
				key = vv
			}
		}
		key = strings.ToLower(strings.TrimSpace(key))
		if len(key) != 64 {
			continue
		}
		out[normalizeKeyPath(k)] = key
	}
	return out
}

func relPathFromDataDir(dataDir, dbFile string) (string, bool) {
	rel, err := filepath.Rel(dataDir, dbFile)
	if err == nil && !strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(rel), true
	}
	dbDir := dataDir
	if !strings.EqualFold(filepath.Base(filepath.Clean(dataDir)), "db_storage") {
		dbDir = filepath.Join(dataDir, "db_storage")
	}
	rel, err = filepath.Rel(dbDir, dbFile)
	if err == nil && !strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(rel), true
	}
	return "", false
}

func normalizeKeyPath(p string) string {
	return strings.TrimPrefix(strings.ToLower(strings.ReplaceAll(filepath.ToSlash(filepath.Clean(p)), "\\", "/")), "./")
}

func isPlainSQLite(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	head := make([]byte, 16)
	n, err := io.ReadFull(f, head)
	if err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return false, nil
		}
		return false, err
	}
	if n < 16 {
		return false, nil
	}
	return string(head) == "SQLite format 3\x00", nil
}

func queryRows(dbPath, query string) ([]map[string]interface{}, error) {
	dsn := fmt.Sprintf("file:%s?mode=ro&_query_only=1", dbPath)
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	raw := make([]interface{}, len(cols))
	dest := make([]interface{}, len(cols))
	for i := range raw {
		dest[i] = &raw[i]
	}

	out := make([]map[string]interface{}, 0)
	for rows.Next() {
		if err := rows.Scan(dest...); err != nil {
			return nil, err
		}
		m := make(map[string]interface{}, len(cols))
		for i, c := range cols {
			v := raw[i]
			switch t := v.(type) {
			case []byte:
				cp := make([]byte, len(t))
				copy(cp, t)
				m[c] = cp
			default:
				m[c] = t
			}
		}
		out = append(out, m)
	}
	return out, nil
}

func toInt64(v interface{}) int64 {
	switch t := v.(type) {
	case int64:
		return t
	case int:
		return int64(t)
	case float64:
		return int64(t)
	case string:
		n := int64(0)
		fmt.Sscan(strings.TrimSpace(t), &n)
		return n
	default:
		return 0
	}
}

func isReadableSQLite(path string) (bool, error) {
	plain, err := isPlainSQLite(path)
	if err != nil || !plain {
		return false, err
	}
	dsn := fmt.Sprintf("file:%s?mode=ro&_query_only=1", path)
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return false, err
	}
	defer db.Close()
	row := db.QueryRow(`SELECT name FROM sqlite_master LIMIT 1`)
	var name string
	if err := row.Scan(&name); err != nil {
		// sqlite_master 为空时也视为可读
		if strings.Contains(strings.ToLower(err.Error()), "no rows") {
			return true, nil
		}
		return false, err
	}
	return true, nil
}

func fileMTimeNS(path string) int64 {
	st, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return st.ModTime().UnixNano()
}

func decodeHexKey(hexKey string) ([]byte, error) {
	b, err := hex.DecodeString(strings.TrimSpace(hexKey))
	if err != nil {
		return nil, err
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("invalid key length: %d", len(b))
	}
	return b, nil
}

const (
	walHeaderSize = 32
	walFrameHdr   = 24
	pageSize      = 4096
	reserveSize   = 80
	saltSize      = 16
)

func applyWAL(walPath, outPath string, encKey []byte) error {
	data, err := os.ReadFile(walPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if len(data) <= walHeaderSize {
		return nil
	}
	s1 := binary.BigEndian.Uint32(data[16:20])
	s2 := binary.BigEndian.Uint32(data[20:24])
	frameSize := walFrameHdr + pageSize
	frames := data[walHeaderSize:]

	dbf, err := os.OpenFile(outPath, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer dbf.Close()

	for pos := 0; pos+frameSize <= len(frames); pos += frameSize {
		fh := frames[pos : pos+walFrameHdr]
		pg := binary.BigEndian.Uint32(fh[0:4])
		if pg == 0 || pg > 1_000_000 {
			continue
		}
		fs1 := binary.BigEndian.Uint32(fh[8:12])
		fs2 := binary.BigEndian.Uint32(fh[12:16])
		if fs1 != s1 || fs2 != s2 {
			continue
		}
		pageBuf := frames[pos+walFrameHdr : pos+frameSize]
		dec, err := decryptWALPage(encKey, pageBuf, pg)
		if err != nil {
			return err
		}
		off := int64(pg-1) * int64(pageSize)
		if _, err := dbf.WriteAt(dec, off); err != nil {
			return err
		}
	}
	return nil
}

func decryptWALPage(key []byte, pageData []byte, pgno uint32) ([]byte, error) {
	// wx-cli 行为：WAL 中第一页按普通页路径解密（不走 salt/header 特殊逻辑）
	if pgno == 1 {
		pgno = 2
	}
	return decryptPageRaw(key, pageData, int(pgno))
}

func decryptPageRaw(key []byte, pageData []byte, pgno int) ([]byte, error) {
	if len(pageData) < pageSize || len(key) != 32 {
		return nil, fmt.Errorf("invalid page or key")
	}
	ivOffset := pageSize - reserveSize
	iv := pageData[ivOffset : ivOffset+16]
	out := make([]byte, pageSize)

	if pgno == 1 {
		enc := pageData[saltSize : pageSize-reserveSize]
		dec, err := aesCBCDecryptRaw(key, iv, enc)
		if err != nil {
			return nil, err
		}
		copy(out[:16], []byte("SQLite format 3\x00"))
		copy(out[16:pageSize-reserveSize], dec)
		return out, nil
	}
	enc := pageData[:pageSize-reserveSize]
	dec, err := aesCBCDecryptRaw(key, iv, enc)
	if err != nil {
		return nil, err
	}
	copy(out[:pageSize-reserveSize], dec)
	return out, nil
}

func aesCBCDecryptRaw(key, iv, data []byte) ([]byte, error) {
	if len(data) == 0 || len(data)%16 != 0 {
		return nil, fmt.Errorf("invalid cipher length: %d", len(data))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	copy(out, data)
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, out)
	return out, nil
}
