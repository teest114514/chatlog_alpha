package semantic

import (
	"crypto/sha1"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type record struct {
	Talker  string
	Seq     int64
	Sender  string
	IsSelf  bool
	Type    int64
	SubType int64
	TS      int64
	Content string
	Model   string
	Dim     int
	Vector  []float64
}

type entityRecord struct {
	Kind        string
	Username    string
	Display     string
	ScopeTalker string
	Aliases     []string
	Content     string
	Model       string
	Dim         int
	Vector      []float64
}

type chunkRecord struct {
	ChunkID  string
	Kind     string
	Talker   string
	StartSeq int64
	EndSeq   int64
	StartTS  int64
	EndTS    int64
	Content  string
	Model    string
	Dim      int
	Vector   []float64
}

type IndexPreviewItem struct {
	Kind         string    `json:"kind"`
	ID           string    `json:"id"`
	Talker       string    `json:"talker,omitempty"`
	Seq          int64     `json:"seq,omitempty"`
	Sender       string    `json:"sender,omitempty"`
	EntityType   string    `json:"entity_type,omitempty"`
	Username     string    `json:"username,omitempty"`
	Display      string    `json:"display,omitempty"`
	ScopeTalker  string    `json:"scope_talker,omitempty"`
	ChunkType    string    `json:"chunk_type,omitempty"`
	StartSeq     int64     `json:"start_seq,omitempty"`
	EndSeq       int64     `json:"end_seq,omitempty"`
	Time         int64     `json:"time,omitempty"`
	StartTime    int64     `json:"start_time,omitempty"`
	EndTime      int64     `json:"end_time,omitempty"`
	Content      string    `json:"content"`
	Model        string    `json:"model"`
	Dim          int       `json:"dim"`
	VectorNorm   float64   `json:"vector_norm"`
	VectorSample []float64 `json:"vector_sample"`
	X            float64   `json:"x"`
	Y            float64   `json:"y"`
	Z            float64   `json:"z"`
	OutlierScore float64   `json:"outlier_score"`
	IsOutlier    bool      `json:"is_outlier"`
	UpdatedAt    int64     `json:"updated_at"`
}

type IndexPreviewGroup struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type IndexPreview struct {
	Model      string              `json:"model"`
	Dim        int                 `json:"dim"`
	Kind       string              `json:"kind"`
	Limit      int                 `json:"limit"`
	Offset     int                 `json:"offset"`
	Total      int                 `json:"total"`
	Groups     []IndexPreviewGroup `json:"groups"`
	Items      []IndexPreviewItem  `json:"items"`
	StorePath  string              `json:"store_path"`
	SampleDims int                 `json:"sample_dims"`
	Outliers   []IndexPreviewItem  `json:"outliers"`
}

type Store struct {
	db   *sql.DB
	path string
	mu   sync.Mutex
}

func OpenStore(workDir string) (*Store, error) {
	baseDir := stringsOr(filepath.Join(os.TempDir(), "chatlog_semantic"), workDir)
	if workDir != "" {
		baseDir = filepath.Join(workDir, ".chatlog_semantic")
	}
	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		return nil, err
	}
	dbPath := filepath.Join(baseDir, "vector_index.db")
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}
	s := &Store{db: db, path: dbPath}
	if err := s.init(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) Path() string { return s.path }

func (s *Store) init() error {
	schema := `
CREATE TABLE IF NOT EXISTS semantic_embeddings (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	talker TEXT NOT NULL,
	seq INTEGER NOT NULL,
	sender TEXT,
	is_self INTEGER NOT NULL DEFAULT 0,
	msg_type INTEGER NOT NULL DEFAULT 0,
	msg_sub_type INTEGER NOT NULL DEFAULT 0,
	ts INTEGER NOT NULL,
	content TEXT NOT NULL,
	content_hash TEXT NOT NULL,
	model TEXT NOT NULL,
	dim INTEGER NOT NULL,
	vector_json TEXT NOT NULL,
	updated_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_semantic_unique ON semantic_embeddings(talker, seq, model, dim);
CREATE INDEX IF NOT EXISTS idx_semantic_talker_ts ON semantic_embeddings(talker, ts);
CREATE INDEX IF NOT EXISTS idx_semantic_ts ON semantic_embeddings(ts);

CREATE TABLE IF NOT EXISTS semantic_entities (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	entity_type TEXT NOT NULL,
	username TEXT NOT NULL,
	scope_talker TEXT NOT NULL DEFAULT '',
	display TEXT NOT NULL,
	aliases_json TEXT NOT NULL,
	content TEXT NOT NULL,
	content_hash TEXT NOT NULL,
	model TEXT NOT NULL,
	dim INTEGER NOT NULL,
	vector_json TEXT NOT NULL,
	updated_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_semantic_entity_unique ON semantic_entities(entity_type, username, scope_talker, model, dim);
CREATE INDEX IF NOT EXISTS idx_semantic_entity_model ON semantic_entities(model, dim);

CREATE TABLE IF NOT EXISTS semantic_chunks (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	chunk_id TEXT NOT NULL,
	chunk_type TEXT NOT NULL,
	talker TEXT NOT NULL,
	start_seq INTEGER NOT NULL,
	end_seq INTEGER NOT NULL,
	start_ts INTEGER NOT NULL,
	end_ts INTEGER NOT NULL,
	content TEXT NOT NULL,
	content_hash TEXT NOT NULL,
	model TEXT NOT NULL,
	dim INTEGER NOT NULL,
	vector_json TEXT NOT NULL,
	updated_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_semantic_chunk_unique ON semantic_chunks(chunk_id, chunk_type, model, dim);
CREATE INDEX IF NOT EXISTS idx_semantic_chunk_talker_ts ON semantic_chunks(talker, start_ts, end_ts);
CREATE INDEX IF NOT EXISTS idx_semantic_chunk_model ON semantic_chunks(model, dim);

CREATE TABLE IF NOT EXISTS semantic_meta (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
`
	_, err := s.db.Exec(schema)
	return err
}

func (s *Store) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`DELETE FROM semantic_embeddings; DELETE FROM semantic_entities; DELETE FROM semantic_chunks`)
	return err
}

func (s *Store) Count() (int, error) {
	row := s.db.QueryRow(`SELECT COUNT(1) FROM semantic_embeddings`)
	var n int
	if err := row.Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

func (s *Store) EntityCount(model string, dim int) (int, error) {
	row := s.db.QueryRow(`SELECT COUNT(1) FROM semantic_entities WHERE model=? AND dim=?`, model, dim)
	var n int
	if err := row.Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

func (s *Store) ChunkCount(model string, dim int) (int, error) {
	row := s.db.QueryRow(`SELECT COUNT(1) FROM semantic_chunks WHERE model=? AND dim=?`, model, dim)
	var n int
	if err := row.Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

func (s *Store) PreviewIndex(kind, model string, dim, limit, offset int) (IndexPreview, error) {
	return s.PreviewIndexScoped(kind, "", model, dim, limit, offset)
}

func (s *Store) PreviewIndexScoped(kind, talker, model string, dim, limit, offset int) (IndexPreview, error) {
	kind = strings.TrimSpace(strings.ToLower(kind))
	talker = strings.TrimSpace(talker)
	if kind == "" {
		kind = "message"
	}
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	out := IndexPreview{
		Model:      model,
		Dim:        dim,
		Kind:       kind,
		Limit:      limit,
		Offset:     offset,
		StorePath:  s.path,
		SampleDims: 16,
	}
	switch kind {
	case "all", "mixed":
		out.Kind = "all"
		out.Total = 0
		msgLimit := maxInt(1, limit/3)
		entityLimit := maxInt(1, limit/3)
		chunkLimit := maxInt(1, limit-msgLimit-entityLimit)
		msgTotal, err := s.previewCountScoped(`semantic_embeddings`, talker, model, dim)
		if err != nil {
			return out, err
		}
		entityTotal, err := s.previewEntityCountScoped(talker, model, dim)
		if err != nil {
			return out, err
		}
		chunkTotal, err := s.previewCountScoped(`semantic_chunks`, talker, model, dim)
		if err != nil {
			return out, err
		}
		out.Total = msgTotal + entityTotal + chunkTotal
		out.Groups = []IndexPreviewGroup{
			{Name: "message", Count: msgTotal},
			{Name: "entity", Count: entityTotal},
			{Name: "chunk", Count: chunkTotal},
		}
		msgItems, err := s.previewMessages(talker, model, dim, msgLimit, offset)
		if err != nil {
			return out, err
		}
		entityItems, err := s.previewEntities(talker, model, dim, entityLimit, offset)
		if err != nil {
			return out, err
		}
		chunkItems, err := s.previewChunks(talker, model, dim, chunkLimit, offset)
		if err != nil {
			return out, err
		}
		out.Items = append(out.Items, msgItems...)
		out.Items = append(out.Items, entityItems...)
		out.Items = append(out.Items, chunkItems...)
	case "entity", "entities":
		out.Kind = "entity"
		total, err := s.previewEntityCountScoped(talker, model, dim)
		if err != nil {
			return out, err
		}
		out.Total = total
		groups, err := s.previewEntityGroups(talker, model, dim)
		if err != nil {
			return out, err
		}
		out.Groups = groups
		items, err := s.previewEntities(talker, model, dim, limit, offset)
		if err != nil {
			return out, err
		}
		out.Items = items
	case "chunk", "chunks":
		out.Kind = "chunk"
		total, err := s.previewCountScoped(`semantic_chunks`, talker, model, dim)
		if err != nil {
			return out, err
		}
		out.Total = total
		groups, err := s.previewGroupsScoped(`semantic_chunks`, `chunk_type`, talker, model, dim)
		if err != nil {
			return out, err
		}
		out.Groups = groups
		items, err := s.previewChunks(talker, model, dim, limit, offset)
		if err != nil {
			return out, err
		}
		out.Items = items
	default:
		out.Kind = "message"
		total, err := s.previewCountScoped(`semantic_embeddings`, talker, model, dim)
		if err != nil {
			return out, err
		}
		out.Total = total
		groups, err := s.previewGroupsScoped(`semantic_embeddings`, `CAST(msg_type AS TEXT)`, talker, model, dim)
		if err != nil {
			return out, err
		}
		out.Groups = groups
		items, err := s.previewMessages(talker, model, dim, limit, offset)
		if err != nil {
			return out, err
		}
		out.Items = items
	}
	normalizePreviewCoordinates(out.Items)
	scorePreviewOutliers(out.Items)
	out.Outliers = topPreviewOutliers(out.Items, 8)
	return out, nil
}

func (s *Store) previewCount(table, model string, dim int) (int, error) {
	row := s.db.QueryRow(`SELECT COUNT(1) FROM `+table+` WHERE model=? AND dim=?`, model, dim)
	var n int
	if err := row.Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

func (s *Store) previewCountScoped(table, talker, model string, dim int) (int, error) {
	talker = strings.TrimSpace(talker)
	query := `SELECT COUNT(1) FROM ` + table + ` WHERE model=? AND dim=?`
	args := []any{model, dim}
	if talker != "" {
		query += ` AND talker=?`
		args = append(args, talker)
	}
	row := s.db.QueryRow(query, args...)
	var n int
	if err := row.Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

func (s *Store) previewEntityCountScoped(talker, model string, dim int) (int, error) {
	talker = strings.TrimSpace(talker)
	query := `SELECT COUNT(1) FROM semantic_entities WHERE model=? AND dim=?`
	args := []any{model, dim}
	if talker != "" {
		query += ` AND (scope_talker=? OR username=? OR entity_type='chatroom' AND username=?)`
		args = append(args, talker, talker, talker)
	}
	row := s.db.QueryRow(query, args...)
	var n int
	if err := row.Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

func (s *Store) previewGroups(query, model string, dim int) ([]IndexPreviewGroup, error) {
	rows, err := s.db.Query(query, model, dim)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []IndexPreviewGroup{}
	for rows.Next() {
		var name string
		var count int
		if err := rows.Scan(&name, &count); err != nil {
			return nil, err
		}
		if strings.TrimSpace(name) == "" {
			name = "-"
		}
		out = append(out, IndexPreviewGroup{Name: name, Count: count})
	}
	return out, rows.Err()
}

func (s *Store) previewGroupsScoped(table, expr, talker, model string, dim int) ([]IndexPreviewGroup, error) {
	talker = strings.TrimSpace(talker)
	query := `SELECT ` + expr + `, COUNT(1) FROM ` + table + ` WHERE model=? AND dim=?`
	args := []any{model, dim}
	if talker != "" {
		query += ` AND talker=?`
		args = append(args, talker)
	}
	query += ` GROUP BY ` + expr + ` ORDER BY COUNT(1) DESC`
	return s.previewGroupsWithArgs(query, args...)
}

func (s *Store) previewEntityGroups(talker, model string, dim int) ([]IndexPreviewGroup, error) {
	talker = strings.TrimSpace(talker)
	query := `SELECT entity_type, COUNT(1) FROM semantic_entities WHERE model=? AND dim=?`
	args := []any{model, dim}
	if talker != "" {
		query += ` AND (scope_talker=? OR username=? OR entity_type='chatroom' AND username=?)`
		args = append(args, talker, talker, talker)
	}
	query += ` GROUP BY entity_type ORDER BY COUNT(1) DESC`
	return s.previewGroupsWithArgs(query, args...)
}

func (s *Store) previewGroupsWithArgs(query string, args ...any) ([]IndexPreviewGroup, error) {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []IndexPreviewGroup{}
	for rows.Next() {
		var name string
		var count int
		if err := rows.Scan(&name, &count); err != nil {
			return nil, err
		}
		if strings.TrimSpace(name) == "" {
			name = "-"
		}
		out = append(out, IndexPreviewGroup{Name: name, Count: count})
	}
	return out, rows.Err()
}

func (s *Store) Coverage(model string, dim int) (int, int64, error) {
	row := s.db.QueryRow(`SELECT COUNT(DISTINCT talker), COALESCE(MAX(ts), 0) FROM semantic_embeddings WHERE model=? AND dim=?`, model, dim)
	var talkers int
	var maxTS int64
	if err := row.Scan(&talkers, &maxTS); err != nil {
		return 0, 0, err
	}
	return talkers, maxTS, nil
}

func (s *Store) MaxSeq(talker, model string, dim int) (int64, error) {
	row := s.db.QueryRow(`SELECT COALESCE(MAX(seq), 0) FROM semantic_embeddings WHERE talker=? AND model=? AND dim=?`, talker, model, dim)
	var n int64
	if err := row.Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

func (s *Store) LoadContentHashes(talker, model string, dim int) (map[int64]string, error) {
	rows, err := s.db.Query(`SELECT seq, content_hash FROM semantic_embeddings WHERE talker=? AND model=? AND dim=?`, talker, model, dim)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]string{}
	for rows.Next() {
		var seq int64
		var hash string
		if err := rows.Scan(&seq, &hash); err != nil {
			return nil, err
		}
		out[seq] = hash
	}
	return out, rows.Err()
}

func (s *Store) previewMessages(talker, model string, dim, limit, offset int) ([]IndexPreviewItem, error) {
	query := `SELECT talker, seq, sender, msg_type, ts, content, model, dim, vector_json, updated_at
FROM semantic_embeddings
WHERE model=? AND dim=?`
	args := []any{model, dim}
	if strings.TrimSpace(talker) != "" {
		query += ` AND talker=?`
		args = append(args, strings.TrimSpace(talker))
	}
	query += ` ORDER BY ts DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]IndexPreviewItem, 0, limit)
	for rows.Next() {
		var item IndexPreviewItem
		var msgType int64
		var vecRaw string
		if err := rows.Scan(&item.Talker, &item.Seq, &item.Sender, &msgType, &item.Time, &item.Content, &item.Model, &item.Dim, &vecRaw, &item.UpdatedAt); err != nil {
			return nil, err
		}
		vec, sample, norm := previewVector(vecRaw, 16)
		x, y, z := projectVector3(vec)
		item.Kind = "message"
		item.ID = fmt.Sprintf("%s:%d", item.Talker, item.Seq)
		item.EntityType = fmt.Sprint(msgType)
		item.VectorNorm = norm
		item.VectorSample = sample
		item.X = x
		item.Y = y
		item.Z = z
		if item.Dim <= 0 {
			item.Dim = len(vec)
		}
		item.Content = previewText(item.Content, 280)
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) previewEntities(talker, model string, dim, limit, offset int) ([]IndexPreviewItem, error) {
	query := `SELECT entity_type, username, scope_talker, display, content, model, dim, vector_json, updated_at
FROM semantic_entities
WHERE model=? AND dim=?`
	args := []any{model, dim}
	if strings.TrimSpace(talker) != "" {
		talker = strings.TrimSpace(talker)
		query += ` AND (scope_talker=? OR username=? OR entity_type='chatroom' AND username=?)`
		args = append(args, talker, talker, talker)
	}
	query += ` ORDER BY updated_at DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]IndexPreviewItem, 0, limit)
	for rows.Next() {
		var item IndexPreviewItem
		var vecRaw string
		if err := rows.Scan(&item.EntityType, &item.Username, &item.ScopeTalker, &item.Display, &item.Content, &item.Model, &item.Dim, &vecRaw, &item.UpdatedAt); err != nil {
			return nil, err
		}
		vec, sample, norm := previewVector(vecRaw, 16)
		x, y, z := projectVector3(vec)
		item.Kind = "entity"
		item.ID = item.EntityType + ":" + item.Username + ":" + item.ScopeTalker
		item.VectorNorm = norm
		item.VectorSample = sample
		item.X = x
		item.Y = y
		item.Z = z
		if item.Dim <= 0 {
			item.Dim = len(vec)
		}
		item.Content = previewText(item.Content, 280)
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) previewChunks(talker, model string, dim, limit, offset int) ([]IndexPreviewItem, error) {
	query := `SELECT chunk_id, chunk_type, talker, start_seq, end_seq, start_ts, end_ts, content, model, dim, vector_json, updated_at
FROM semantic_chunks
WHERE model=? AND dim=?`
	args := []any{model, dim}
	if strings.TrimSpace(talker) != "" {
		query += ` AND talker=?`
		args = append(args, strings.TrimSpace(talker))
	}
	query += ` ORDER BY end_ts DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]IndexPreviewItem, 0, limit)
	for rows.Next() {
		var item IndexPreviewItem
		var vecRaw string
		if err := rows.Scan(&item.ID, &item.ChunkType, &item.Talker, &item.StartSeq, &item.EndSeq, &item.StartTime, &item.EndTime, &item.Content, &item.Model, &item.Dim, &vecRaw, &item.UpdatedAt); err != nil {
			return nil, err
		}
		vec, sample, norm := previewVector(vecRaw, 16)
		x, y, z := projectVector3(vec)
		item.Kind = "chunk"
		item.VectorNorm = norm
		item.VectorSample = sample
		item.X = x
		item.Y = y
		item.Z = z
		if item.Dim <= 0 {
			item.Dim = len(vec)
		}
		item.Content = previewText(item.Content, 360)
		out = append(out, item)
	}
	return out, rows.Err()
}

func previewVector(raw string, sampleSize int) ([]float64, []float64, float64) {
	var vec []float64
	_ = json.Unmarshal([]byte(raw), &vec)
	n := sampleSize
	if n <= 0 || n > len(vec) {
		n = len(vec)
	}
	sample := make([]float64, 0, n)
	var sum float64
	for i, v := range vec {
		sum += v * v
		if i < n {
			sample = append(sample, v)
		}
	}
	return vec, sample, sqrtApprox(sum)
}

func projectVector3(vec []float64) (float64, float64, float64) {
	if len(vec) == 0 {
		return 0, 0, 0
	}
	var x, y, z float64
	for i, v := range vec {
		x += v * projectionWeight(i, 0)
		y += v * projectionWeight(i, 1)
		z += v * projectionWeight(i, 2)
	}
	scale := sqrtApprox(float64(len(vec)))
	if scale <= 0 {
		scale = 1
	}
	return x / scale, y / scale, z / scale
}

func projectionWeight(i, axis int) float64 {
	x := uint64(i+1)*0x9e3779b97f4a7c15 + uint64(axis+1)*0xbf58476d1ce4e5b9
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	x ^= x >> 31
	return float64(int(x%2001)-1000) / 1000
}

func normalizePreviewCoordinates(items []IndexPreviewItem) {
	if len(items) == 0 {
		return
	}
	var cx, cy, cz float64
	for _, item := range items {
		cx += item.X
		cy += item.Y
		cz += item.Z
	}
	cx /= float64(len(items))
	cy /= float64(len(items))
	cz /= float64(len(items))
	var maxAbs float64
	for i := range items {
		items[i].X -= cx
		items[i].Y -= cy
		items[i].Z -= cz
		maxAbs = maxFloat64(maxAbs, absFloat64(items[i].X))
		maxAbs = maxFloat64(maxAbs, absFloat64(items[i].Y))
		maxAbs = maxFloat64(maxAbs, absFloat64(items[i].Z))
	}
	if maxAbs <= 0 {
		return
	}
	for i := range items {
		items[i].X /= maxAbs
		items[i].Y /= maxAbs
		items[i].Z /= maxAbs
	}
}

func scorePreviewOutliers(items []IndexPreviewItem) {
	if len(items) < 4 {
		return
	}
	scores := make([]float64, len(items))
	for i := range items {
		ds := make([]float64, 0, len(items)-1)
		for j := range items {
			if i == j {
				continue
			}
			dx := items[i].X - items[j].X
			dy := items[i].Y - items[j].Y
			dz := items[i].Z - items[j].Z
			ds = append(ds, sqrtApprox(dx*dx+dy*dy+dz*dz))
		}
		sortFloat64s(ds)
		k := 3
		if len(ds) < k {
			k = len(ds)
		}
		var sum float64
		for n := 0; n < k; n++ {
			sum += ds[n]
		}
		if k > 0 {
			scores[i] = sum / float64(k)
			items[i].OutlierScore = scores[i]
		}
	}
	threshold := percentileFloat64(scores, 0.9)
	for i := range items {
		items[i].IsOutlier = items[i].OutlierScore > 0 && items[i].OutlierScore >= threshold
	}
}

func topPreviewOutliers(items []IndexPreviewItem, limit int) []IndexPreviewItem {
	out := make([]IndexPreviewItem, 0, len(items))
	for _, item := range items {
		if item.IsOutlier {
			out = append(out, item)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].OutlierScore > out[j].OutlierScore })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func sortFloat64s(items []float64) {
	sort.Slice(items, func(i, j int) bool { return items[i] < items[j] })
}

func percentileFloat64(items []float64, p float64) float64 {
	if len(items) == 0 {
		return 0
	}
	cp := append([]float64(nil), items...)
	sortFloat64s(cp)
	if p < 0 {
		p = 0
	}
	if p > 1 {
		p = 1
	}
	idx := int(float64(len(cp)-1) * p)
	return cp[idx]
}

func sqrtApprox(v float64) float64 {
	if v <= 0 {
		return 0
	}
	x := v
	for i := 0; i < 8; i++ {
		x = 0.5 * (x + v/x)
	}
	return x
}

func absFloat64(v float64) float64 {
	if v < 0 {
		return -v
	}
	return v
}

func maxFloat64(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func previewText(s string, limit int) string {
	s = strings.Join(strings.Fields(strings.TrimSpace(s)), " ")
	if limit > 0 && len([]rune(s)) > limit {
		return string([]rune(s)[:limit]) + "..."
	}
	return s
}

func (s *Store) Upsert(records []record) error {
	if len(records) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`
INSERT INTO semantic_embeddings(
	talker, seq, sender, is_self, msg_type, msg_sub_type, ts,
	content, content_hash, model, dim, vector_json, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(talker, seq, model, dim) DO UPDATE SET
	sender=excluded.sender,
	is_self=excluded.is_self,
	msg_type=excluded.msg_type,
	msg_sub_type=excluded.msg_sub_type,
	ts=excluded.ts,
	content=excluded.content,
	content_hash=excluded.content_hash,
	vector_json=excluded.vector_json,
	updated_at=excluded.updated_at
`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()

	now := time.Now().Unix()
	for _, item := range records {
		vecRaw, err := json.Marshal(item.Vector)
		if err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err := stmt.Exec(
			item.Talker, item.Seq, item.Sender, boolToInt(item.IsSelf), item.Type, item.SubType, item.TS,
			item.Content, hashText(item.Content), item.Model, item.Dim, string(vecRaw), now,
		); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) LoadEntityHashes(model string, dim int) (map[string]string, error) {
	rows, err := s.db.Query(`SELECT entity_type, username, scope_talker, content_hash FROM semantic_entities WHERE model=? AND dim=?`, model, dim)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var kind, username, scope, hash string
		if err := rows.Scan(&kind, &username, &scope, &hash); err != nil {
			return nil, err
		}
		out[entityKey(kind, username, scope)] = hash
	}
	return out, rows.Err()
}

func (s *Store) UpsertEntities(records []entityRecord) error {
	if len(records) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`
INSERT INTO semantic_entities(
	entity_type, username, scope_talker, display, aliases_json,
	content, content_hash, model, dim, vector_json, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(entity_type, username, scope_talker, model, dim) DO UPDATE SET
	display=excluded.display,
	aliases_json=excluded.aliases_json,
	content=excluded.content,
	content_hash=excluded.content_hash,
	vector_json=excluded.vector_json,
	updated_at=excluded.updated_at
`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()

	now := time.Now().Unix()
	for _, item := range records {
		aliasRaw, err := json.Marshal(item.Aliases)
		if err != nil {
			_ = tx.Rollback()
			return err
		}
		vecRaw, err := json.Marshal(item.Vector)
		if err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err := stmt.Exec(
			item.Kind, item.Username, item.ScopeTalker, item.Display, string(aliasRaw),
			item.Content, hashText(item.Content), item.Model, item.Dim, string(vecRaw), now,
		); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) LoadEntityCandidates(model string, dim, limit int) ([]entityRecord, error) {
	if limit <= 0 {
		limit = 10000
	}
	rows, err := s.db.Query(`SELECT entity_type, username, scope_talker, display, aliases_json, content, model, dim, vector_json
FROM semantic_entities
WHERE model=? AND dim=?
ORDER BY updated_at DESC
LIMIT ?`, model, dim, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]entityRecord, 0, limit)
	for rows.Next() {
		var item entityRecord
		var aliasRaw string
		var vecRaw string
		if err := rows.Scan(&item.Kind, &item.Username, &item.ScopeTalker, &item.Display, &aliasRaw, &item.Content, &item.Model, &item.Dim, &vecRaw); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(aliasRaw), &item.Aliases)
		if err := json.Unmarshal([]byte(vecRaw), &item.Vector); err != nil {
			continue
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func entityKey(kind, username, scope string) string {
	return strings.TrimSpace(kind) + "\x00" + strings.TrimSpace(username) + "\x00" + strings.TrimSpace(scope)
}

func (s *Store) DeleteChunksForTalker(talker, model string, dim int) error {
	talker = strings.TrimSpace(talker)
	if talker == "" || strings.TrimSpace(model) == "" || dim <= 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`DELETE FROM semantic_chunks WHERE talker=? AND model=? AND dim=?`, talker, model, dim)
	return err
}

func (s *Store) LoadChunkHashes(talker, model string, dim int) (map[string]string, error) {
	talker = strings.TrimSpace(talker)
	if talker == "" || strings.TrimSpace(model) == "" || dim <= 0 {
		return map[string]string{}, nil
	}
	rows, err := s.db.Query(`SELECT chunk_id, chunk_type, content_hash FROM semantic_chunks WHERE talker=? AND model=? AND dim=?`, talker, model, dim)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, kind, hash string
		if err := rows.Scan(&id, &kind, &hash); err != nil {
			return nil, err
		}
		out[chunkStoreKey(id, kind)] = hash
	}
	return out, rows.Err()
}

func (s *Store) LastChunkStartSeq(talker, model string, dim int) (int64, error) {
	talker = strings.TrimSpace(talker)
	if talker == "" || strings.TrimSpace(model) == "" || dim <= 0 {
		return 0, nil
	}
	row := s.db.QueryRow(`SELECT COALESCE(MAX(start_seq), 0) FROM semantic_chunks WHERE talker=? AND model=? AND dim=? AND chunk_type='session'`, talker, model, dim)
	var seq int64
	if err := row.Scan(&seq); err != nil {
		return 0, err
	}
	return seq, nil
}

func (s *Store) DeleteChunksFromSeq(talker, model string, dim int, startSeq int64) error {
	talker = strings.TrimSpace(talker)
	if talker == "" || strings.TrimSpace(model) == "" || dim <= 0 || startSeq <= 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`DELETE FROM semantic_chunks WHERE talker=? AND model=? AND dim=? AND end_seq>=?`, talker, model, dim, startSeq)
	return err
}

func (s *Store) DeleteStaleChunks(talker, model string, dim int, keepKeys map[string]struct{}, minEndSeq int64) error {
	talker = strings.TrimSpace(talker)
	if talker == "" || strings.TrimSpace(model) == "" || dim <= 0 {
		return nil
	}
	query := `SELECT chunk_id, chunk_type FROM semantic_chunks WHERE talker=? AND model=? AND dim=?`
	args := []any{talker, model, dim}
	if minEndSeq > 0 {
		query += ` AND end_seq>=?`
		args = append(args, minEndSeq)
	}
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return err
	}
	var stale [][2]string
	for rows.Next() {
		var id, kind string
		if err := rows.Scan(&id, &kind); err != nil {
			_ = rows.Close()
			return err
		}
		if _, ok := keepKeys[chunkStoreKey(id, kind)]; !ok {
			stale = append(stale, [2]string{id, kind})
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if len(stale) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`DELETE FROM semantic_chunks WHERE talker=? AND chunk_id=? AND chunk_type=? AND model=? AND dim=?`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, item := range stale {
		if _, err := stmt.Exec(talker, item[0], item[1], model, dim); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func chunkStoreKey(id, kind string) string {
	return strings.TrimSpace(kind) + "\x00" + strings.TrimSpace(id)
}

func (s *Store) UpsertChunks(records []chunkRecord) error {
	if len(records) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`
INSERT INTO semantic_chunks(
	chunk_id, chunk_type, talker, start_seq, end_seq, start_ts, end_ts,
	content, content_hash, model, dim, vector_json, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(chunk_id, chunk_type, model, dim) DO UPDATE SET
	talker=excluded.talker,
	start_seq=excluded.start_seq,
	end_seq=excluded.end_seq,
	start_ts=excluded.start_ts,
	end_ts=excluded.end_ts,
	content=excluded.content,
	content_hash=excluded.content_hash,
	vector_json=excluded.vector_json,
	updated_at=excluded.updated_at
`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()

	now := time.Now().Unix()
	for _, item := range records {
		vecRaw, err := json.Marshal(item.Vector)
		if err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err := stmt.Exec(
			item.ChunkID, item.Kind, item.Talker, item.StartSeq, item.EndSeq, item.StartTS, item.EndTS,
			item.Content, hashText(item.Content), item.Model, item.Dim, string(vecRaw), now,
		); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) LoadChunkCandidatesScoped(talkers []string, startTS, endTS int64, model string, dim, limit int) ([]chunkRecord, error) {
	if limit <= 0 {
		limit = 3000
	}
	query := `SELECT chunk_id, chunk_type, talker, start_seq, end_seq, start_ts, end_ts, content, model, dim, vector_json
FROM semantic_chunks
WHERE model=? AND dim=?`
	args := []any{model, dim}
	talkers = normalizeTalkerScope(talkers)
	if len(talkers) > 0 {
		query += ` AND talker IN (` + placeholders(len(talkers)) + `)`
		for _, talker := range talkers {
			args = append(args, talker)
		}
	}
	if startTS > 0 {
		query += ` AND end_ts>=?`
		args = append(args, startTS)
	}
	if endTS > 0 {
		query += ` AND start_ts<=?`
		args = append(args, endTS)
	}
	query += ` ORDER BY end_ts DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]chunkRecord, 0, limit)
	for rows.Next() {
		var item chunkRecord
		var vecRaw string
		if err := rows.Scan(&item.ChunkID, &item.Kind, &item.Talker, &item.StartSeq, &item.EndSeq, &item.StartTS, &item.EndTS, &item.Content, &item.Model, &item.Dim, &vecRaw); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(vecRaw), &item.Vector); err != nil {
			continue
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) DeleteOne(talker string, seq int64, model string, dim int) error {
	if strings.TrimSpace(talker) == "" || seq <= 0 || strings.TrimSpace(model) == "" || dim <= 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`DELETE FROM semantic_embeddings WHERE talker=? AND seq=? AND model=? AND dim=?`, talker, seq, model, dim)
	return err
}

func (s *Store) LoadCandidates(talker, model string, dim, limit int) ([]record, error) {
	var talkers []string
	if strings.TrimSpace(talker) != "" {
		talkers = []string{strings.TrimSpace(talker)}
	}
	return s.LoadCandidatesScoped(talkers, 0, 0, model, dim, limit)
}

func (s *Store) LoadCandidatesScoped(talkers []string, startTS, endTS int64, model string, dim, limit int) ([]record, error) {
	if limit <= 0 {
		limit = 5000
	}
	query := `SELECT talker, seq, sender, is_self, msg_type, msg_sub_type, ts, content, model, dim, vector_json
FROM semantic_embeddings
WHERE model=? AND dim=?`
	args := []any{model, dim}
	talkers = normalizeTalkerScope(talkers)
	if len(talkers) > 0 {
		query += ` AND talker IN (` + placeholders(len(talkers)) + `)`
		for _, talker := range talkers {
			args = append(args, talker)
		}
	}
	if startTS > 0 {
		query += ` AND ts>=?`
		args = append(args, startTS)
	}
	if endTS > 0 {
		query += ` AND ts<=?`
		args = append(args, endTS)
	}
	query += ` ORDER BY ts DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]record, 0, limit)
	for rows.Next() {
		var item record
		var isSelf int
		var vecRaw string
		if err := rows.Scan(
			&item.Talker, &item.Seq, &item.Sender, &isSelf, &item.Type, &item.SubType,
			&item.TS, &item.Content, &item.Model, &item.Dim, &vecRaw,
		); err != nil {
			return nil, err
		}
		item.IsSelf = isSelf == 1
		if err := json.Unmarshal([]byte(vecRaw), &item.Vector); err != nil {
			continue
		}
		out = append(out, item)
	}
	return out, nil
}

func (s *Store) LoadCandidatesBalancedScoped(talkers []string, startTS, endTS int64, model string, dim, limit int) ([]record, error) {
	if limit <= 0 {
		limit = 5000
	}
	if limit <= 6000 {
		return s.LoadCandidatesScoped(talkers, startTS, endTS, model, dim, limit)
	}

	recentLimit := limit / 3
	if recentLimit < 3000 {
		recentLimit = 3000
	}
	recent, err := s.LoadCandidatesScoped(talkers, startTS, endTS, model, dim, recentLimit)
	if err != nil {
		return nil, err
	}
	out := make([]record, 0, limit)
	seen := make(map[string]struct{}, limit)
	add := func(items []record) {
		for _, item := range items {
			if len(out) >= limit {
				return
			}
			key := item.Talker + "\x00" + fmt.Sprint(item.Seq)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, item)
		}
	}
	add(recent)
	if len(out) >= limit {
		return out, nil
	}

	minTS, maxTS, err := s.MinMaxTSScoped(talkers, startTS, endTS, model, dim)
	if err != nil {
		return nil, err
	}
	if minTS <= 0 || maxTS <= 0 || maxTS <= minTS {
		return out, nil
	}
	bins := 8
	remaining := limit - len(out)
	perBin := remaining / bins
	if perBin < 250 {
		perBin = 250
	}
	span := maxTS - minTS + 1
	for i := 0; i < bins && len(out) < limit; i++ {
		lo := minTS + int64(i)*span/int64(bins)
		hi := minTS + int64(i+1)*span/int64(bins) - 1
		if i == bins-1 {
			hi = maxTS
		}
		items, err := s.LoadCandidatesScoped(talkers, lo, hi, model, dim, perBin)
		if err != nil {
			return nil, err
		}
		add(items)
	}
	return out, nil
}

func (s *Store) MinMaxTSScoped(talkers []string, startTS, endTS int64, model string, dim int) (int64, int64, error) {
	query := `SELECT COALESCE(MIN(ts), 0), COALESCE(MAX(ts), 0)
FROM semantic_embeddings
WHERE model=? AND dim=?`
	args := []any{model, dim}
	talkers = normalizeTalkerScope(talkers)
	if len(talkers) > 0 {
		query += ` AND talker IN (` + placeholders(len(talkers)) + `)`
		for _, talker := range talkers {
			args = append(args, talker)
		}
	}
	if startTS > 0 {
		query += ` AND ts>=?`
		args = append(args, startTS)
	}
	if endTS > 0 {
		query += ` AND ts<=?`
		args = append(args, endTS)
	}
	var minTS, maxTS int64
	if err := s.db.QueryRow(query, args...).Scan(&minTS, &maxTS); err != nil {
		return 0, 0, err
	}
	return minTS, maxTS, nil
}

// SearchByKeywords returns records whose content column contains any of the given
// keywords (SQL LIKE %kw%). Results are deduplicated and limited to bound the
// worst-case row count.
func (s *Store) SearchByKeywords(talker, model string, dim int, keywords []string, limit int) ([]record, error) {
	var talkers []string
	if strings.TrimSpace(talker) != "" {
		talkers = []string{strings.TrimSpace(talker)}
	}
	return s.SearchByKeywordsScoped(talkers, 0, 0, model, dim, keywords, limit)
}

func (s *Store) SearchByKeywordsScoped(talkers []string, startTS, endTS int64, model string, dim int, keywords []string, limit int) ([]record, error) {
	if len(keywords) == 0 || limit <= 0 {
		return nil, nil
	}
	baseQuery := `SELECT talker, seq, sender, is_self, msg_type, msg_sub_type, ts, content, model, dim, vector_json
	FROM semantic_embeddings
	WHERE model=? AND dim=?`
	args := []any{model, dim}
	talkers = normalizeTalkerScope(talkers)
	if len(talkers) > 0 {
		baseQuery += ` AND talker IN (` + placeholders(len(talkers)) + `)`
		for _, talker := range talkers {
			args = append(args, talker)
		}
	}
	if startTS > 0 {
		baseQuery += ` AND ts>=?`
		args = append(args, startTS)
	}
	if endTS > 0 {
		baseQuery += ` AND ts<=?`
		args = append(args, endTS)
	}
	var clauses []string
	for _, kw := range keywords {
		clauses = append(clauses, `content LIKE ?`)
		args = append(args, `%`+kw+`%`)
	}
	baseQuery += ` AND (` + strings.Join(clauses, ` OR `) + `) ORDER BY ts DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.Query(baseQuery, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]record, 0, limit)
	for rows.Next() {
		var item record
		var isSelf int
		var vecRaw string
		if err := rows.Scan(
			&item.Talker, &item.Seq, &item.Sender, &isSelf, &item.Type, &item.SubType,
			&item.TS, &item.Content, &item.Model, &item.Dim, &vecRaw,
		); err != nil {
			return nil, err
		}
		item.IsSelf = isSelf == 1
		_ = json.Unmarshal([]byte(vecRaw), &item.Vector)
		out = append(out, item)
	}
	return out, rows.Err()
}

func normalizeTalkerScope(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	seen := map[string]struct{}{}
	for _, item := range in {
		talker := strings.TrimSpace(item)
		if talker == "" {
			continue
		}
		if _, ok := seen[talker]; ok {
			continue
		}
		seen[talker] = struct{}{}
		out = append(out, talker)
	}
	return out
}

func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	parts := make([]string, n)
	for i := range parts {
		parts[i] = "?"
	}
	return strings.Join(parts, ",")
}

func (s *Store) LoadContext(talker, model string, dim int, centerSeq int64, before, after int) ([]record, error) {
	if strings.TrimSpace(talker) == "" || centerSeq <= 0 || (before <= 0 && after <= 0) {
		return nil, nil
	}
	prev, err := s.loadContextSide(talker, model, dim, centerSeq, before, true)
	if err != nil {
		return nil, err
	}
	next, err := s.loadContextSide(talker, model, dim, centerSeq, after, false)
	if err != nil {
		return nil, err
	}
	out := make([]record, 0, len(prev)+len(next))
	out = append(out, prev...)
	out = append(out, next...)
	return out, nil
}

func (s *Store) loadContextSide(talker, model string, dim int, centerSeq int64, limit int, before bool) ([]record, error) {
	if limit <= 0 {
		return nil, nil
	}
	op := ">"
	order := "ASC"
	if before {
		op = "<"
		order = "DESC"
	}
	query := fmt.Sprintf(`SELECT talker, seq, sender, is_self, msg_type, msg_sub_type, ts, content, model, dim, vector_json
FROM semantic_embeddings
WHERE talker=? AND model=? AND dim=? AND seq%s?
ORDER BY seq %s
LIMIT ?`, op, order)
	rows, err := s.db.Query(query, talker, model, dim, centerSeq, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]record, 0, limit)
	for rows.Next() {
		var item record
		var isSelf int
		var vecRaw string
		if err := rows.Scan(
			&item.Talker, &item.Seq, &item.Sender, &isSelf, &item.Type, &item.SubType,
			&item.TS, &item.Content, &item.Model, &item.Dim, &vecRaw,
		); err != nil {
			return nil, err
		}
		item.IsSelf = isSelf == 1
		_ = json.Unmarshal([]byte(vecRaw), &item.Vector)
		out = append(out, item)
	}
	if before {
		for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
			out[i], out[j] = out[j], out[i]
		}
	}
	return out, rows.Err()
}

func (s *Store) SaveMeta(key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT INTO semantic_meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

func (s *Store) DeleteMeta(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`DELETE FROM semantic_meta WHERE key=?`, key)
	return err
}

func (s *Store) GetMeta(key string) (string, error) {
	row := s.db.QueryRow(`SELECT value FROM semantic_meta WHERE key=?`, key)
	var value string
	if err := row.Scan(&value); err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		return "", err
	}
	return value, nil
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func stringsOr(primary, fallback string) string {
	if strings.TrimSpace(primary) != "" {
		return primary
	}
	return fallback
}

func hashText(s string) string {
	h := sha1.Sum([]byte(s))
	return fmt.Sprintf("%x", h[:])
}
