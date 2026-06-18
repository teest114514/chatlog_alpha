package semantic

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDoJSONRequestReadsLargeSuccessfulResponse(t *testing.T) {
	const vectorLen = 220000

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"embeddings":[[`)
		for i := 0; i < vectorLen; i++ {
			if i > 0 {
				_, _ = fmt.Fprint(w, ",")
			}
			_, _ = fmt.Fprint(w, "0.123456789")
		}
		_, _ = fmt.Fprint(w, `]]}`)
	}))
	defer server.Close()

	client := &Client{httpClient: server.Client()}
	var out struct {
		Embeddings [][]float64 `json:"embeddings"`
	}

	err := client.doJSONRequest(context.Background(), "", server.URL, map[string]any{"model": "test"}, &out)
	if err != nil {
		t.Fatalf("doJSONRequest failed for large successful response: %v", err)
	}
	if len(out.Embeddings) != 1 {
		t.Fatalf("expected one embedding, got %d", len(out.Embeddings))
	}
	if got := len(out.Embeddings[0]); got != vectorLen {
		t.Fatalf("expected vector length %d, got %d", vectorLen, got)
	}
}
