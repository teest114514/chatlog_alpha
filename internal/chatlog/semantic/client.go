package semantic

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sjzar/chatlog/internal/chatlog/conf"
)

const (
	maxEmbeddingBatch       = 64
	maxEmbeddingInputTokens = 3072
	maxModelErrorBodyBytes  = 2 * 1024 * 1024
	maxModelSuccessBytes    = 64 * 1024 * 1024
	maxRerankTotalChars     = 30000 // GLM rerank limits query+documents to 32k chars
	maxRerankDocs           = 80    // cap docs sent to reranker
	maxOllamaRerankDocs     = 20    // local generation-based rerank is much slower than hosted rerank APIs
	maxRerankDocChars       = 400   // per-doc char ceiling for reranker
)

var ollamaScheduler = &ollamaModelScheduler{}

type ollamaModelScheduler struct {
	mu          sync.Mutex
	client      *Client
	base        string
	model       string
	phase       string
	lastTouched time.Time
}

func (s *ollamaModelScheduler) Begin(ctx context.Context, c *Client, base, model, phase string) func() {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if base == "" {
		base = conf.DefaultOllamaBaseURL
	}
	model = strings.TrimSpace(model)
	phase = strings.TrimSpace(phase)
	s.mu.Lock()
	if s.model != "" && (s.base != base || s.model != model || s.phase != phase) {
		s.client.unloadOllamaModel(ctx, s.base, s.model)
	}
	s.client = c
	s.base = base
	s.model = model
	s.phase = phase
	s.lastTouched = time.Now()
	return func() {
		s.lastTouched = time.Now()
		s.mu.Unlock()
	}
}

func (s *ollamaModelScheduler) Release(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.client == nil || s.model == "" {
		return
	}
	s.client.unloadOllamaModel(ctx, s.base, s.model)
	s.client = nil
	s.base = ""
	s.model = ""
	s.phase = ""
	s.lastTouched = time.Time{}
}

type Client struct {
	httpClient *http.Client
}

func NewClient() *Client {
	return &Client{
		httpClient: &http.Client{Timeout: 45 * time.Second},
	}
}

func (c *Client) Test(ctx context.Context, cfg conf.SemanticConfig) error {
	cfg = conf.NormalizeSemanticConfig(cfg)
	if _, err := c.Embed(ctx, cfg, []string{"连通性测试"}); err != nil {
		return err
	}
	if cfg.EnableRerank {
		if _, err := c.Rerank(ctx, cfg, "连通性测试", []string{"连接正常", "无关内容"}, 1); err != nil {
			ollamaScheduler.Release(context.Background())
			return err
		}
	}
	if conf.SemanticChatReady(cfg) {
		_, err := c.Chat(ctx, cfg, []ChatMessage{
			{Role: "user", Content: "请用一句话回复：连接正常。"},
		})
		ollamaScheduler.Release(context.Background())
		return err
	}
	ollamaScheduler.Release(context.Background())
	return nil
}

func (c *Client) Embed(ctx context.Context, cfg conf.SemanticConfig, inputs []string) ([][]float64, error) {
	cfg = conf.NormalizeSemanticConfig(cfg)
	inputs = sanitizeInputs(inputs)
	if len(inputs) == 0 {
		return nil, nil
	}
	if cfg.EmbeddingProvider == conf.ProviderOllama {
		return c.embedOllama(ctx, cfg, inputs)
	}
	out := make([][]float64, 0, len(inputs))
	for i := 0; i < len(inputs); i += maxEmbeddingBatch {
		end := i + maxEmbeddingBatch
		if end > len(inputs) {
			end = len(inputs)
		}
		vecs, err := c.embedBatch(ctx, cfg, inputs[i:end])
		if err != nil {
			return nil, err
		}
		out = append(out, vecs...)
	}
	return out, nil
}

func (c *Client) embedBatch(ctx context.Context, cfg conf.SemanticConfig, inputs []string) ([][]float64, error) {
	cfg = conf.NormalizeSemanticConfig(cfg)
	base := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if base == "" {
		base = conf.DefaultGLMBaseURL
	}
	payload := map[string]any{
		"model": cfg.EmbeddingModel,
		"input": inputs,
	}
	if cfg.EmbeddingDimension > 0 {
		payload["dimensions"] = cfg.EmbeddingDimension
	}
	var resp struct {
		Data []struct {
			Embedding []float64 `json:"embedding"`
			Index     int       `json:"index"`
		} `json:"data"`
		Error map[string]any `json:"error"`
	}
	if err := c.doJSON(ctx, cfg.APIKey, base+"/embeddings", payload, &resp); err != nil {
		return nil, err
	}
	if len(resp.Error) > 0 {
		return nil, fmt.Errorf("embedding error: %v", resp.Error)
	}
	out := make([][]float64, len(inputs))
	for _, item := range resp.Data {
		if item.Index >= 0 && item.Index < len(out) {
			out[item.Index] = item.Embedding
		}
	}
	for i := range out {
		if len(out[i]) == 0 {
			return nil, fmt.Errorf("embedding missing vector at index %d", i)
		}
	}
	return out, nil
}

func (c *Client) embedOllama(ctx context.Context, cfg conf.SemanticConfig, inputs []string) ([][]float64, error) {
	base := strings.TrimRight(strings.TrimSpace(cfg.OllamaBaseURL), "/")
	if base == "" {
		base = conf.DefaultOllamaBaseURL
	}
	done := ollamaScheduler.Begin(ctx, c, base, cfg.EmbeddingModel, "embedding")
	defer done()
	out := make([][]float64, 0, len(inputs))
	for i := 0; i < len(inputs); i += maxEmbeddingBatch {
		end := i + maxEmbeddingBatch
		if end > len(inputs) {
			end = len(inputs)
		}
		payload := map[string]any{
			"model":      cfg.EmbeddingModel,
			"input":      inputs[i:end],
			"keep_alive": "30s",
		}
		var resp struct {
			Embeddings [][]float64 `json:"embeddings"`
			Embedding  []float64   `json:"embedding"`
			Error      string      `json:"error"`
			Data       []struct {
				Embedding []float64 `json:"embedding"`
				Index     int       `json:"index"`
			} `json:"data"`
		}
		if err := c.doJSONNoAuth(ctx, base+"/api/embed", payload, &resp); err != nil {
			return nil, err
		}
		if resp.Error != "" {
			return nil, fmt.Errorf("ollama embedding error: %s", resp.Error)
		}
		vecs, err := normalizeEmbeddingResponse(resp.Embeddings, resp.Embedding, resp.Data, len(inputs[i:end]))
		if err != nil {
			return nil, err
		}
		out = append(out, vecs...)
	}
	return out, nil
}

func normalizeEmbeddingResponse(embeddings [][]float64, embedding []float64, data []struct {
	Embedding []float64 `json:"embedding"`
	Index     int       `json:"index"`
}, count int) ([][]float64, error) {
	if len(embeddings) == count {
		return embeddings, nil
	}
	if count == 1 && len(embedding) > 0 {
		return [][]float64{embedding}, nil
	}
	if len(data) > 0 {
		out := make([][]float64, count)
		for _, item := range data {
			if item.Index >= 0 && item.Index < len(out) {
				out[item.Index] = item.Embedding
			}
		}
		for i := range out {
			if len(out[i]) == 0 {
				return nil, fmt.Errorf("ollama embedding missing vector at index %d", i)
			}
		}
		return out, nil
	}
	return nil, fmt.Errorf("ollama embedding returned %d vectors for %d inputs", len(embeddings), count)
}

type RerankItem struct {
	Index int
	Score float64
}

func (c *Client) Rerank(ctx context.Context, cfg conf.SemanticConfig, query string, docs []string, topN int) ([]RerankItem, error) {
	cfg = conf.NormalizeSemanticConfig(cfg)
	query = strings.TrimSpace(query)
	docs = sanitizeInputs(docs)
	if query == "" || len(docs) == 0 {
		return nil, nil
	}
	if cfg.RerankProvider == conf.ProviderOllama {
		return c.rerankOllama(ctx, cfg, query, docs, topN)
	}
	// Enforce GLM's 32k-char limit on query+documents by capping doc count,
	// truncating each doc, and ensuring the total fits the budget.
	if len(docs) > maxRerankDocs {
		docs = docs[:maxRerankDocs]
		if topN > maxRerankDocs {
			topN = maxRerankDocs
		}
	}
	queryChars := len([]rune(query))
	perDocBudget := (maxRerankTotalChars - queryChars) / len(docs)
	if perDocBudget < 80 {
		perDocBudget = 80
	}
	if perDocBudget > maxRerankDocChars {
		perDocBudget = maxRerankDocChars
	}
	for i := range docs {
		runes := []rune(docs[i])
		if len(runes) > perDocBudget {
			docs[i] = string(runes[:perDocBudget])
		}
	}
	base := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if base == "" {
		base = conf.DefaultGLMBaseURL
	}
	if topN <= 0 || topN > len(docs) {
		topN = len(docs)
	}
	payload := map[string]any{
		"model":            cfg.RerankModel,
		"query":            query,
		"documents":        docs,
		"top_n":            topN,
		"return_documents": false,
	}
	var resp struct {
		Results []struct {
			Index          int     `json:"index"`
			RelevanceScore float64 `json:"relevance_score"`
		} `json:"results"`
		Error map[string]any `json:"error"`
	}
	if err := c.doJSON(ctx, cfg.APIKey, base+"/rerank", payload, &resp); err != nil {
		return nil, err
	}
	if len(resp.Error) > 0 {
		return nil, fmt.Errorf("rerank error: %v", resp.Error)
	}
	out := make([]RerankItem, 0, len(resp.Results))
	for _, item := range resp.Results {
		out = append(out, RerankItem{
			Index: item.Index,
			Score: item.RelevanceScore,
		})
	}
	return out, nil
}

func (c *Client) rerankOllama(ctx context.Context, cfg conf.SemanticConfig, query string, docs []string, topN int) ([]RerankItem, error) {
	base := strings.TrimRight(strings.TrimSpace(cfg.OllamaBaseURL), "/")
	if base == "" {
		base = conf.DefaultOllamaBaseURL
	}
	done := ollamaScheduler.Begin(ctx, c, base, cfg.RerankModel, "rerank")
	defer done()
	if len(docs) > maxOllamaRerankDocs {
		docs = docs[:maxOllamaRerankDocs]
	}
	if topN <= 0 || topN > len(docs) {
		topN = len(docs)
	}
	type scored struct {
		Index int
		Score float64
	}
	scoredItems := make([]scored, 0, len(docs))
	for i, doc := range docs {
		score, err := c.ollamaRerankScore(ctx, cfg, base, query, doc)
		if err != nil {
			return nil, err
		}
		scoredItems = append(scoredItems, scored{Index: i, Score: score})
	}
	sort.SliceStable(scoredItems, func(i, j int) bool {
		return scoredItems[i].Score > scoredItems[j].Score
	})
	out := make([]RerankItem, 0, topN)
	for i := 0; i < topN && i < len(scoredItems); i++ {
		out = append(out, RerankItem{Index: scoredItems[i].Index, Score: scoredItems[i].Score})
	}
	return out, nil
}

func (c *Client) ollamaRerankScore(ctx context.Context, cfg conf.SemanticConfig, base, query, doc string) (float64, error) {
	if len([]rune(doc)) > maxRerankDocChars {
		doc = string([]rune(doc)[:maxRerankDocChars])
	}
	prompt := fmt.Sprintf("请判断文档与查询的相关性，只输出 0 到 1 之间的分数，不要解释。\n查询：%s\n文档：%s\n分数：", query, doc)
	payload := map[string]any{
		"model":      cfg.RerankModel,
		"prompt":     prompt,
		"stream":     false,
		"keep_alive": "30s",
		"options": map[string]any{
			"temperature": 0,
			"num_predict": 8,
		},
	}
	var resp struct {
		Response string `json:"response"`
		Error    string `json:"error"`
	}
	if err := c.doJSONNoAuth(ctx, base+"/api/generate", payload, &resp); err != nil {
		return 0, err
	}
	if resp.Error != "" {
		return 0, fmt.Errorf("ollama rerank error: %s", resp.Error)
	}
	score, ok := parseFirstFloat(resp.Response)
	if !ok {
		return 0, fmt.Errorf("ollama rerank returned non-score response: %s", trimSnippet([]byte(resp.Response), 120))
	}
	if score < 0 {
		score = 0
	}
	if score > 1 {
		score = 1
	}
	return score, nil
}

type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

func (c *Client) Chat(ctx context.Context, cfg conf.SemanticConfig, messages []ChatMessage) (string, error) {
	cfg = conf.NormalizeSemanticConfig(cfg)
	clean := make([]ChatMessage, 0, len(messages))
	for _, msg := range messages {
		role := strings.TrimSpace(msg.Role)
		content := strings.TrimSpace(msg.Content)
		if role == "" || content == "" {
			continue
		}
		clean = append(clean, ChatMessage{Role: role, Content: content})
	}
	if len(clean) == 0 {
		return "", nil
	}
	if cfg.ChatProvider == conf.ProviderOllama {
		return c.chatOllama(ctx, cfg, clean)
	}
	if cfg.ChatProvider == conf.ProviderDeepSeek {
		return c.chatOpenAICompatible(ctx, cfg.DeepSeekAPIKey, cfg.DeepSeekBaseURL, cfg.ChatModel, clean, cfg.ChatThinking, cfg.ChatMaxTokens, cfg.ChatTemperature)
	}
	if !conf.SemanticChatReady(cfg) {
		return "", fmt.Errorf("chat model is not configured")
	}
	return c.chatOpenAICompatible(ctx, cfg.APIKey, cfg.BaseURL, cfg.ChatModel, clean, cfg.ChatThinking, cfg.ChatMaxTokens, cfg.ChatTemperature)
}

func (c *Client) chatOpenAICompatible(ctx context.Context, apiKey, baseURL, model string, messages []ChatMessage, thinking bool, maxTokens int, temperature float64) (string, error) {
	base := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if base == "" {
		base = conf.DefaultGLMBaseURL
	}
	thinkingType := "disabled"
	if thinking {
		thinkingType = "enabled"
	}
	payload := map[string]any{
		"model":       model,
		"messages":    messages,
		"thinking":    map[string]any{"type": thinkingType},
		"max_tokens":  maxTokens,
		"temperature": temperature,
	}
	var resp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Error map[string]any `json:"error"`
	}
	if err := c.doJSON(ctx, apiKey, base+"/chat/completions", payload, &resp); err != nil {
		return "", err
	}
	if len(resp.Error) > 0 {
		return "", fmt.Errorf("chat error: %v", resp.Error)
	}
	if len(resp.Choices) == 0 {
		return "", fmt.Errorf("chat returned empty choices")
	}
	answer := strings.TrimSpace(resp.Choices[0].Message.Content)
	if answer == "" {
		return "", fmt.Errorf("chat returned empty content")
	}
	return answer, nil
}

func (c *Client) chatOllama(ctx context.Context, cfg conf.SemanticConfig, messages []ChatMessage) (string, error) {
	base := strings.TrimRight(strings.TrimSpace(cfg.OllamaBaseURL), "/")
	if base == "" {
		base = conf.DefaultOllamaBaseURL
	}
	done := ollamaScheduler.Begin(ctx, c, base, cfg.ChatModel, "chat")
	defer done()
	payload := map[string]any{
		"model":      cfg.ChatModel,
		"messages":   messages,
		"stream":     false,
		"keep_alive": "30s",
		"options": map[string]any{
			"temperature": cfg.ChatTemperature,
			"num_predict": cfg.ChatMaxTokens,
		},
	}
	var resp struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		Response string `json:"response"`
		Error    string `json:"error"`
	}
	if err := c.doJSONNoAuth(ctx, base+"/api/chat", payload, &resp); err != nil {
		return "", err
	}
	if resp.Error != "" {
		return "", fmt.Errorf("ollama chat error: %s", resp.Error)
	}
	answer := strings.TrimSpace(resp.Message.Content)
	if answer == "" {
		answer = strings.TrimSpace(resp.Response)
	}
	if answer == "" {
		return "", fmt.Errorf("ollama chat returned empty content")
	}
	return answer, nil
}

func (c *Client) ChatStream(ctx context.Context, cfg conf.SemanticConfig, messages []ChatMessage, onDelta func(string) error) error {
	cfg = conf.NormalizeSemanticConfig(cfg)
	clean := make([]ChatMessage, 0, len(messages))
	for _, msg := range messages {
		role := strings.TrimSpace(msg.Role)
		content := strings.TrimSpace(msg.Content)
		if role == "" || content == "" {
			continue
		}
		clean = append(clean, ChatMessage{Role: role, Content: content})
	}
	if len(clean) == 0 {
		return nil
	}
	if cfg.ChatProvider == conf.ProviderOllama {
		answer, err := c.chatOllama(ctx, cfg, clean)
		if err != nil {
			return err
		}
		if onDelta != nil {
			return onDelta(answer)
		}
		return nil
	}
	if !conf.SemanticChatReady(cfg) {
		return fmt.Errorf("chat model is not configured")
	}
	apiKey := cfg.APIKey
	base := cfg.BaseURL
	if cfg.ChatProvider == conf.ProviderDeepSeek {
		apiKey = cfg.DeepSeekAPIKey
		base = cfg.DeepSeekBaseURL
	}
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if base == "" {
		base = conf.DefaultGLMBaseURL
	}
	thinkingType := "disabled"
	if cfg.ChatThinking {
		thinkingType = "enabled"
	}
	payload := map[string]any{
		"model":       cfg.ChatModel,
		"messages":    clean,
		"thinking":    map[string]any{"type": thinkingType},
		"stream":      true,
		"max_tokens":  cfg.ChatMaxTokens,
		"temperature": cfg.ChatTemperature,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(apiKey))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
		return fmt.Errorf("chat http %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, ":") {
			continue
		}
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if data == "" || data == "[DONE]" {
			continue
		}
		delta, err := parseChatStreamDelta([]byte(data))
		if err != nil {
			return err
		}
		if delta == "" {
			continue
		}
		if onDelta != nil {
			if err := onDelta(delta); err != nil {
				return err
			}
		}
	}
	return scanner.Err()
}

func parseChatStreamDelta(raw []byte) (string, error) {
	var payload struct {
		Choices []struct {
			Delta struct {
				Content          string `json:"content"`
				ReasoningContent string `json:"reasoning_content"`
			} `json:"delta"`
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Error map[string]any `json:"error"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", fmt.Errorf("decode glm stream failed: %w; response_snippet=%q", err, trimSnippet(raw, 260))
	}
	if len(payload.Error) > 0 {
		return "", fmt.Errorf("glm chat stream error: %v", payload.Error)
	}
	if len(payload.Choices) == 0 {
		return "", nil
	}
	if payload.Choices[0].Delta.Content != "" {
		return payload.Choices[0].Delta.Content, nil
	}
	return payload.Choices[0].Message.Content, nil
}

func (c *Client) doJSON(ctx context.Context, apiKey, url string, reqBody any, out any) error {
	if strings.TrimSpace(apiKey) == "" {
		return fmt.Errorf("glm api key is empty")
	}
	return c.doJSONRequest(ctx, apiKey, url, reqBody, out)
}

func (c *Client) doJSONNoAuth(ctx context.Context, url string, reqBody any, out any) error {
	return c.doJSONRequest(ctx, "", url, reqBody, out)
}

func (c *Client) unloadOllamaModel(ctx context.Context, base, model string) {
	model = strings.TrimSpace(model)
	if model == "" {
		return
	}
	if base = strings.TrimRight(strings.TrimSpace(base), "/"); base == "" {
		base = conf.DefaultOllamaBaseURL
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	payload := map[string]any{
		"model":      model,
		"prompt":     "",
		"stream":     false,
		"keep_alive": 0,
	}
	var out map[string]any
	if err := c.doJSONNoAuth(ctx, base+"/api/generate", payload, &out); err == nil {
		return
	}
	embedPayload := map[string]any{
		"model":      model,
		"input":      "",
		"keep_alive": 0,
	}
	_ = c.doJSONNoAuth(ctx, base+"/api/embed", embedPayload, &out)
}

func (c *Client) doJSONRequest(ctx context.Context, apiKey, url string, reqBody any, out any) error {
	body, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if strings.TrimSpace(apiKey) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(apiKey))
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	bodyLimit := int64(maxModelSuccessBytes)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodyLimit = maxModelErrorBodyBytes
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, bodyLimit+1))
	if err != nil {
		return err
	}
	if int64(len(raw)) > bodyLimit {
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("model http %d: response body exceeds %d bytes", resp.StatusCode, bodyLimit)
		}
		return fmt.Errorf("model response exceeds %d bytes", bodyLimit)
	}
	raw = bytes.TrimPrefix(raw, []byte{0xEF, 0xBB, 0xBF}) // utf-8 BOM guard
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("model http %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if err := json.Unmarshal(raw, out); err != nil {
		// Some upstream gateways occasionally return malformed numeric literals like "0. 123".
		// Repair this specific pattern and retry once.
		if strings.Contains(err.Error(), "after decimal point in numeric literal") {
			if fixed := fixBrokenJSONNumbers(raw); len(fixed) > 0 && !bytes.Equal(fixed, raw) {
				if err2 := json.Unmarshal(fixed, out); err2 == nil {
					return nil
				}
			}
		}
		return fmt.Errorf("decode model response failed: %w; response_snippet=%q", err, trimSnippet(raw, 260))
	}
	return nil
}

func sanitizeInputs(in []string) []string {
	out := make([]string, 0, len(in))
	for _, item := range in {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		out = append(out, truncateApproxTokens(item, maxEmbeddingInputTokens))
	}
	return out
}

func truncateApproxTokens(s string, maxTokens int) string {
	if maxTokens <= 0 {
		return s
	}
	runes := []rune(s)
	if len(runes) <= maxTokens {
		return s
	}
	return string(runes[:maxTokens])
}

var brokenNumRe = regexp.MustCompile(`([0-9])\.\s+([0-9])`)

func fixBrokenJSONNumbers(in []byte) []byte {
	// Best-effort repair only; keeps behavior unchanged for valid JSON.
	s := string(in)
	for i := 0; i < 8; i++ {
		next := brokenNumRe.ReplaceAllString(s, `$1.$2`)
		if next == s {
			break
		}
		s = next
	}
	return []byte(s)
}

func trimSnippet(in []byte, n int) string {
	s := strings.TrimSpace(string(in))
	if n <= 0 || len([]rune(s)) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n]) + "..."
}

func parseFirstFloat(raw string) (float64, bool) {
	m := regexp.MustCompile(`[-+]?(?:\d+(?:\.\d*)?|\.\d+)`).FindString(strings.TrimSpace(raw))
	if m == "" {
		return 0, false
	}
	v, err := strconv.ParseFloat(m, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}
