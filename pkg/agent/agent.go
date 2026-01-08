package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// LLMClient handles communication with the LLM API
type LLMClient struct {
	token string
}

// NewLLMClient creates a new LLM client instance
func NewLLMClient(token string) *LLMClient {
	return &LLMClient{
		token: token,
	}
}

// CallLLM sends a prompt to the LLM and returns the parsed JSON response
func (c *LLMClient) CallLLM(ctx context.Context, prompt string) (map[string]interface{}, error) {
	reqBody, err := json.Marshal(map[string]interface{}{
		"model": "gpt-4o",
		"messages": []map[string]string{
			{"role": "system", "content": "You are a technical analyzer. Always return valid JSON."},
			{"role": "user", "content": prompt},
		},
		"temperature":     0.1,
		"max_tokens":      1000,
		"response_format": map[string]string{"type": "json_object"},
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "https://models.inference.ai.azure.com/chat/completions", strings.NewReader(string(reqBody)))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("⚠️  LLM failed: %v\n", err)
		return map[string]interface{}{}, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		fmt.Printf("⚠️  LLM API returned %d: %s\n", resp.StatusCode, string(body))
		return map[string]interface{}{}, nil
	}

	var llmResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&llmResp); err != nil {
		return nil, err
	}

	if len(llmResp.Choices) == 0 {
		return map[string]interface{}{}, nil
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(llmResp.Choices[0].Message.Content), &parsed); err != nil {
		return nil, err
	}

	return parsed, nil
}

// CallLLMRaw sends a prompt to the LLM and returns the raw text response (not JSON)
func (c *LLMClient) CallLLMRaw(ctx context.Context, prompt string) (string, error) {
	reqBody, err := json.Marshal(map[string]interface{}{
		"model": "gpt-4o",
		"messages": []map[string]string{
			{"role": "system", "content": "You are a helpful assistant."},
			{"role": "user", "content": prompt},
		},
		"temperature": 0.1,
		"max_tokens":  4000,
	})
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "https://models.inference.ai.azure.com/chat/completions", strings.NewReader(string(reqBody)))
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("LLM request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("LLM API returned %d: %s", resp.StatusCode, string(body))
	}

	var llmResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&llmResp); err != nil {
		return "", err
	}

	if len(llmResp.Choices) == 0 {
		return "", fmt.Errorf("no response from LLM")
	}

	return llmResp.Choices[0].Message.Content, nil
}
