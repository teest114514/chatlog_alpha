package conf

import "strings"

const (
	ProviderOllama   = "ollama"
	ProviderGLM      = "glm"
	ProviderDeepSeek = "deepseek"

	DefaultOllamaBaseURL      = "http://127.0.0.1:11434"
	DefaultOllamaEmbedding    = "qwen3-embedding:8b"
	DefaultOllamaRerank       = "dengcao/Qwen3-Reranker-8B:Q5_K_M"
	DefaultOllamaChat         = "qwen3:8b"
	DefaultOllamaEmbeddingDim = 4096
	OllamaQwen3Embedding4BDim = 2560
	DefaultGLMBaseURL         = "https://open.bigmodel.cn/api/paas/v4"
	DefaultGLMEmbedding       = "embedding-3"
	DefaultGLMRerank          = "rerank"
	DefaultGLMChat            = "glm-5.1"
	DefaultGLMEmbeddingDim    = 2048
	DefaultDeepSeekBaseURL    = "https://api.deepseek.com"
	DefaultDeepSeekChat       = "deepseek-chat"
	DefaultSemanticRecallK    = 80
	DefaultSemanticTopN       = 20
	DefaultSemanticThreshold  = 0.55
	DefaultSemanticWorkers    = 1
	DefaultSemanticMaxTokens  = 4096
	DefaultSemanticTemp       = 0.3
)

type SemanticConfig struct {
	Enabled             bool    `mapstructure:"enabled" json:"enabled"`
	APIKey              string  `mapstructure:"api_key" json:"api_key"`
	BaseURL             string  `mapstructure:"base_url" json:"base_url"`
	OllamaBaseURL       string  `mapstructure:"ollama_base_url" json:"ollama_base_url"`
	DeepSeekAPIKey      string  `mapstructure:"deepseek_api_key" json:"deepseek_api_key"`
	DeepSeekBaseURL     string  `mapstructure:"deepseek_base_url" json:"deepseek_base_url"`
	EmbeddingProvider   string  `mapstructure:"embedding_provider" json:"embedding_provider"`
	RerankProvider      string  `mapstructure:"rerank_provider" json:"rerank_provider"`
	ChatProvider        string  `mapstructure:"chat_provider" json:"chat_provider"`
	EmbeddingModel      string  `mapstructure:"embedding_model" json:"embedding_model"`
	RerankModel         string  `mapstructure:"rerank_model" json:"rerank_model"`
	ChatModel           string  `mapstructure:"chat_model" json:"chat_model"`
	ChatThinking        bool    `mapstructure:"chat_thinking" json:"chat_thinking"`
	ChatMaxTokens       int     `mapstructure:"chat_max_tokens" json:"chat_max_tokens"`
	ChatTemperature     float64 `mapstructure:"chat_temperature" json:"chat_temperature"`
	EmbeddingDimension  int     `mapstructure:"embedding_dimension" json:"embedding_dimension"`
	EnableRerank        bool    `mapstructure:"enable_rerank" json:"enable_rerank"`
	EnableQA            bool    `mapstructure:"enable_qa" json:"enable_qa"`
	EnableTopics        bool    `mapstructure:"enable_topics" json:"enable_topics"`
	EnableProfiles      bool    `mapstructure:"enable_profiles" json:"enable_profiles"`
	EnableLLMChunk      bool    `mapstructure:"enable_llm_chunk" json:"enable_llm_chunk"`
	RealtimeIndex       bool    `mapstructure:"realtime_index" json:"realtime_index"`
	IndexWorkers        int     `mapstructure:"index_workers" json:"index_workers"`
	// IndexChatrooms, if non-empty, limits semantic indexing to ONLY these
	// chatroom/contact UserNames (e.g. "25462231499@chatroom"). Other talkers
	// are skipped entirely. Useful when the WeChat DB has 500+ contacts but
	// you only want semantic search over a curated subset, or when a specific
	// talker hangs SQL reads and blocks the entire indexer pipeline.
	// Empty slice = index everything (default behavior).
	IndexChatrooms      []string `mapstructure:"index_chatrooms" json:"index_chatrooms"`
	RecallK             int     `mapstructure:"recall_k" json:"recall_k"`
	TopN                int     `mapstructure:"top_n" json:"top_n"`
	SimilarityThreshold float64 `mapstructure:"similarity_threshold" json:"similarity_threshold"`
}

func NormalizeSemanticConfig(in SemanticConfig) SemanticConfig {
	out := in
	out.BaseURL = strings.TrimSpace(out.BaseURL)
	if out.BaseURL == "" {
		out.BaseURL = DefaultGLMBaseURL
	}
	out.OllamaBaseURL = strings.TrimSpace(out.OllamaBaseURL)
	if out.OllamaBaseURL == "" {
		out.OllamaBaseURL = DefaultOllamaBaseURL
	}
	out.DeepSeekBaseURL = strings.TrimSpace(out.DeepSeekBaseURL)
	if out.DeepSeekBaseURL == "" {
		out.DeepSeekBaseURL = DefaultDeepSeekBaseURL
	}
	out.DeepSeekAPIKey = strings.TrimSpace(out.DeepSeekAPIKey)
	out.EmbeddingProvider = normalizeRetrievalProvider(out.EmbeddingProvider, ProviderOllama)
	out.RerankProvider = normalizeRetrievalProvider(out.RerankProvider, ProviderOllama)
	out.ChatProvider = normalizeProvider(out.ChatProvider, ProviderGLM)
	out.EmbeddingModel = strings.TrimSpace(out.EmbeddingModel)
	if out.EmbeddingProvider == ProviderOllama && (out.EmbeddingModel == "" || out.EmbeddingModel == DefaultGLMEmbedding) {
		out.EmbeddingModel = DefaultOllamaEmbedding
	}
	if out.EmbeddingProvider == ProviderGLM && (out.EmbeddingModel == "" || out.EmbeddingModel == DefaultOllamaEmbedding) {
		out.EmbeddingModel = DefaultGLMEmbedding
	}
	out.RerankModel = strings.TrimSpace(out.RerankModel)
	if out.RerankProvider == ProviderOllama && (out.RerankModel == "" || out.RerankModel == DefaultGLMRerank) {
		out.RerankModel = DefaultOllamaRerank
	}
	if out.RerankProvider == ProviderGLM && (out.RerankModel == "" || out.RerankModel == DefaultOllamaRerank) {
		out.RerankModel = DefaultGLMRerank
	}
	out.ChatModel = strings.TrimSpace(out.ChatModel)
	if out.ChatProvider == ProviderOllama && (out.ChatModel == "" || out.ChatModel == DefaultGLMChat || out.ChatModel == DefaultDeepSeekChat) {
		out.ChatModel = DefaultOllamaChat
	}
	if out.ChatProvider == ProviderDeepSeek && (out.ChatModel == "" || out.ChatModel == DefaultGLMChat || out.ChatModel == DefaultOllamaChat) {
		out.ChatModel = DefaultDeepSeekChat
	}
	if out.ChatProvider == ProviderGLM && (out.ChatModel == "" || out.ChatModel == DefaultDeepSeekChat || out.ChatModel == DefaultOllamaChat) {
		out.ChatModel = DefaultGLMChat
	}
	if out.ChatMaxTokens <= 0 {
		out.ChatMaxTokens = DefaultSemanticMaxTokens
	}
	if out.ChatMaxTokens > 32768 {
		out.ChatMaxTokens = 32768
	}
	if out.ChatTemperature <= 0 || out.ChatTemperature > 2 {
		out.ChatTemperature = DefaultSemanticTemp
	}
	if out.EmbeddingProvider == ProviderOllama {
		if knownDim := KnownOllamaEmbeddingDimension(out.EmbeddingModel); knownDim > 0 {
			out.EmbeddingDimension = knownDim
		} else if out.EmbeddingModel == DefaultOllamaEmbedding && (out.EmbeddingDimension <= 0 || out.EmbeddingDimension == DefaultGLMEmbeddingDim) {
			out.EmbeddingDimension = DefaultOllamaEmbeddingDim
		}
	}
	if out.EmbeddingProvider == ProviderGLM && out.EmbeddingModel == DefaultGLMEmbedding && (out.EmbeddingDimension <= 0 || out.EmbeddingDimension == DefaultOllamaEmbeddingDim) {
		out.EmbeddingDimension = DefaultGLMEmbeddingDim
	}
	if out.EmbeddingDimension < 256 || out.EmbeddingDimension > 8192 {
		switch out.EmbeddingProvider {
		case ProviderOllama:
			out.EmbeddingDimension = DefaultOllamaEmbeddingDim
		default:
			out.EmbeddingDimension = DefaultGLMEmbeddingDim
		}
	}
	if out.RecallK <= 0 {
		out.RecallK = DefaultSemanticRecallK
	}
	if out.IndexWorkers <= 0 {
		out.IndexWorkers = DefaultSemanticWorkers
	}
	if out.IndexWorkers > 32 {
		out.IndexWorkers = 32
	}
	if out.TopN <= 0 {
		out.TopN = DefaultSemanticTopN
	}
	if out.TopN > out.RecallK {
		out.TopN = out.RecallK
	}
	if out.SimilarityThreshold <= 0 || out.SimilarityThreshold > 1 {
		out.SimilarityThreshold = DefaultSemanticThreshold
	}
	return out
}

func KnownOllamaEmbeddingDimension(model string) int {
	switch strings.ToLower(strings.TrimSpace(model)) {
	case "qwen3-embedding:4b":
		return OllamaQwen3Embedding4BDim
	case DefaultOllamaEmbedding:
		return DefaultOllamaEmbeddingDim
	default:
		return 0
	}
}

func normalizeProvider(raw, fallback string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case ProviderOllama:
		return ProviderOllama
	case ProviderGLM:
		return ProviderGLM
	case ProviderDeepSeek:
		return ProviderDeepSeek
	default:
		return fallback
	}
}

func normalizeRetrievalProvider(raw, fallback string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case ProviderOllama:
		return ProviderOllama
	case ProviderGLM:
		return ProviderGLM
	default:
		return fallback
	}
}

func SemanticEmbeddingReady(cfg SemanticConfig) bool {
	cfg = NormalizeSemanticConfig(cfg)
	switch cfg.EmbeddingProvider {
	case ProviderOllama:
		return strings.TrimSpace(cfg.OllamaBaseURL) != "" && strings.TrimSpace(cfg.EmbeddingModel) != ""
	case ProviderGLM:
		return strings.TrimSpace(cfg.BaseURL) != "" && strings.TrimSpace(cfg.APIKey) != "" && strings.TrimSpace(cfg.EmbeddingModel) != ""
	default:
		return false
	}
}

func SemanticRerankReady(cfg SemanticConfig) bool {
	cfg = NormalizeSemanticConfig(cfg)
	if !cfg.EnableRerank {
		return false
	}
	switch cfg.RerankProvider {
	case ProviderOllama:
		return strings.TrimSpace(cfg.OllamaBaseURL) != "" && strings.TrimSpace(cfg.RerankModel) != ""
	case ProviderGLM:
		return strings.TrimSpace(cfg.BaseURL) != "" && strings.TrimSpace(cfg.APIKey) != "" && strings.TrimSpace(cfg.RerankModel) != ""
	default:
		return false
	}
}

func SemanticChatReady(cfg SemanticConfig) bool {
	cfg = NormalizeSemanticConfig(cfg)
	switch cfg.ChatProvider {
	case ProviderOllama:
		return strings.TrimSpace(cfg.OllamaBaseURL) != "" && strings.TrimSpace(cfg.ChatModel) != ""
	case ProviderGLM:
		return strings.TrimSpace(cfg.BaseURL) != "" && strings.TrimSpace(cfg.APIKey) != "" && strings.TrimSpace(cfg.ChatModel) != ""
	case ProviderDeepSeek:
		return strings.TrimSpace(cfg.DeepSeekBaseURL) != "" && strings.TrimSpace(cfg.DeepSeekAPIKey) != "" && strings.TrimSpace(cfg.ChatModel) != ""
	default:
		return false
	}
}
