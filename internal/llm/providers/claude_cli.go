package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/ihavespoons/hooksy/internal/llm"
)

// ClaudeCLIProvider implements the Provider interface using Claude CLI tools.
type ClaudeCLIProvider struct {
	binaryPath string
	model      string
	maxTokens  int
	available  bool
	mu         sync.RWMutex
}

// NewClaudeCLIProvider creates a new Claude CLI provider.
func NewClaudeCLIProvider(cfg *llm.Config) (llm.Provider, error) {
	cliCfg := cfg.Providers.ClaudeCLI
	if !cliCfg.Enabled {
		return nil, fmt.Errorf("claude_cli provider is disabled")
	}

	p := &ClaudeCLIProvider{
		binaryPath: cliCfg.BinaryPath,
		model:      cliCfg.Model,
		maxTokens:  cliCfg.MaxTokens,
	}

	// Auto-detect binary if not specified
	if p.binaryPath == "" {
		p.binaryPath = detectClaudeBinary()
	}

	// Check availability
	p.available = p.binaryPath != ""

	return p, nil
}

// detectClaudeBinary looks for claude or opencode in PATH.
func detectClaudeBinary() string {
	// Try claude first
	if path, err := exec.LookPath("claude"); err == nil {
		return path
	}

	// Try opencode as fallback
	if path, err := exec.LookPath("opencode"); err == nil {
		return path
	}

	return ""
}

// Type returns the provider type.
func (p *ClaudeCLIProvider) Type() llm.ProviderType {
	return llm.ProviderClaudeCLI
}

// Name returns the human-readable provider name.
func (p *ClaudeCLIProvider) Name() string {
	if p.binaryPath != "" {
		// Extract just the binary name
		parts := strings.Split(p.binaryPath, "/")
		return fmt.Sprintf("Claude CLI (%s)", parts[len(parts)-1])
	}
	return "Claude CLI"
}

// Available checks if the provider is available.
func (p *ClaudeCLIProvider) Available(ctx context.Context) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.available
}

// Analyze performs analysis using the Claude CLI.
func (p *ClaudeCLIProvider) Analyze(ctx context.Context, req *llm.AnalysisRequest) (*llm.AnalysisResponse, error) {
	if !p.available {
		return nil, fmt.Errorf("claude CLI is not available")
	}

	// Build the prompt
	prompt := buildAnalysisPrompt(req)

	// Build command arguments
	args := []string{
		"--print",
		"--output-format", "json",
	}

	if p.model != "" {
		args = append(args, "--model", p.model)
	}

	// Note: Claude CLI doesn't support --max-tokens, it has --max-budget-usd instead
	// We skip token limiting for CLI provider as it's typically subscription-based

	// Add the prompt as positional argument (not a --prompt flag)
	args = append(args, prompt)

	// Create command
	cmd := exec.CommandContext(ctx, p.binaryPath, args...)
	cmd.Env = os.Environ()

	// Capture output
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Run command
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("claude CLI failed: %w (stderr: %s)", err, stderr.String())
	}

	// Parse response
	return p.parseResponse(stdout.Bytes())
}

// parseResponse parses the CLI JSON output into an AnalysisResponse.
func (p *ClaudeCLIProvider) parseResponse(output []byte) (*llm.AnalysisResponse, error) {
	// The CLI outputs the result directly, we need to parse the text response
	// and extract structured data from it

	// First try to parse as JSON in case the LLM returned structured output
	var structured StructuredAnalysisResponse
	if err := json.Unmarshal(output, &structured); err == nil && structured.Decision != "" {
		return &llm.AnalysisResponse{
			Decision:     llm.AnalysisDecision(structured.Decision),
			Confidence:   structured.Confidence,
			Reasoning:    structured.Reasoning,
			Findings:     convertFindings(structured.Findings),
			ProviderType: llm.ProviderClaudeCLI,
		}, nil
	}

	// If not JSON, parse as text response
	text := strings.TrimSpace(string(output))
	return parseTextResponse(text, llm.ProviderClaudeCLI)
}

// EstimateCost estimates the cost for analysis (free for CLI tools).
func (p *ClaudeCLIProvider) EstimateCost(req *llm.AnalysisRequest) float64 {
	return 0 // CLI tools are subscription-based, no per-request cost
}

// Close releases any resources.
func (p *ClaudeCLIProvider) Close() error {
	return nil
}

// StructuredAnalysisResponse is the expected JSON structure from the LLM.
type StructuredAnalysisResponse struct {
	Decision   string                      `json:"decision"`
	Confidence float32                     `json:"confidence"`
	Reasoning  string                      `json:"reasoning"`
	Findings   []StructuredFinding         `json:"findings,omitempty"`
}

// StructuredFinding represents a finding in the structured response.
type StructuredFinding struct {
	Category    string `json:"category"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Evidence    string `json:"evidence,omitempty"`
	Location    string `json:"location,omitempty"`
}

// convertFindings converts structured findings to llm.Finding.
func convertFindings(findings []StructuredFinding) []llm.Finding {
	result := make([]llm.Finding, len(findings))
	for i, f := range findings {
		result[i] = llm.Finding{
			Category:    f.Category,
			Severity:    f.Severity,
			Description: f.Description,
			Evidence:    f.Evidence,
			Location:    f.Location,
		}
	}
	return result
}

// parseTextResponse extracts decision and reasoning from plain text response.
func parseTextResponse(text string, providerType llm.ProviderType) (*llm.AnalysisResponse, error) {
	resp := &llm.AnalysisResponse{
		Decision:     llm.DecisionAllow, // Default to allow
		Confidence:   0.5,
		Reasoning:    text,
		ProviderType: providerType,
	}

	// Look for decision keywords
	textLower := strings.ToLower(text)

	if strings.Contains(textLower, "block") || strings.Contains(textLower, "critical") {
		resp.Decision = llm.DecisionBlock
		resp.Confidence = 0.8
	} else if strings.Contains(textLower, "deny") || strings.Contains(textLower, "reject") {
		resp.Decision = llm.DecisionDeny
		resp.Confidence = 0.8
	} else if strings.Contains(textLower, "ask") || strings.Contains(textLower, "unclear") || strings.Contains(textLower, "suspicious") {
		resp.Decision = llm.DecisionAsk
		resp.Confidence = 0.6
	} else if strings.Contains(textLower, "allow") || strings.Contains(textLower, "safe") || strings.Contains(textLower, "legitimate") {
		resp.Decision = llm.DecisionAllow
		resp.Confidence = 0.8
	}

	return resp, nil
}

// buildAnalysisPrompt creates the prompt for the LLM based on the request type.
func buildAnalysisPrompt(req *llm.AnalysisRequest) string {
	var sb strings.Builder

	// Add system prompt if provided
	if req.SystemPrompt != "" {
		sb.WriteString(req.SystemPrompt)
		sb.WriteString("\n\n")
	} else {
		sb.WriteString("You are a security analyzer for an AI coding assistant. ")
		sb.WriteString("Analyze the following and respond with a JSON object containing: ")
		sb.WriteString(`{"decision": "allow|deny|ask|block", "confidence": 0.0-1.0, "reasoning": "explanation", "findings": []}`)
		sb.WriteString("\n\n")
	}

	// Use custom prompt if provided, otherwise use default
	if req.CustomPrompt != "" {
		sb.WriteString(expandPromptTemplate(req.CustomPrompt, req))
	} else {
		sb.WriteString(buildDefaultPrompt(req))
	}

	// Add rule context if available
	if req.RuleDecision != "" {
		sb.WriteString(fmt.Sprintf("\n\nRule-based evaluation: %s (%s)\n", req.RuleDecision, req.RuleReason))
		sb.WriteString("Consider this in your analysis but provide independent judgment.")
	}

	return sb.String()
}

// buildDefaultPrompt builds the default prompt based on analysis type.
func buildDefaultPrompt(req *llm.AnalysisRequest) string {
	var sb strings.Builder

	switch req.Type {
	case llm.AnalysisContextual:
		sb.WriteString("## Contextual Analysis Request\n\n")
		sb.WriteString(fmt.Sprintf("Event Type: %s\n", req.EventType))
		sb.WriteString(fmt.Sprintf("Tool Name: %s\n", req.ToolName))
		if req.ToolInput != nil {
			inputJSON, _ := json.MarshalIndent(req.ToolInput, "", "  ")
			sb.WriteString(fmt.Sprintf("Tool Input:\n```json\n%s\n```\n\n", inputJSON))
		}
		sb.WriteString("Analyze if this tool call is suspicious given the context. ")
		sb.WriteString("Consider: Is this a common operation? Could this be malicious? ")
		sb.WriteString("Is the input trying to bypass security controls?")

	case llm.AnalysisTranscript:
		sb.WriteString("## Transcript Analysis Request\n\n")
		sb.WriteString(fmt.Sprintf("Session ID: %s\n", req.SessionID))
		if req.TranscriptPath != "" {
			sb.WriteString(fmt.Sprintf("Transcript Path: %s\n", req.TranscriptPath))
		}
		sb.WriteString("\nAnalyze the session for: deception, goal hijacking, ")
		sb.WriteString("sandbagging, unauthorized actions, or data exfiltration attempts.")

	case llm.AnalysisIntentAction:
		sb.WriteString("## Intent vs Action Analysis\n\n")
		sb.WriteString(fmt.Sprintf("Tool Name: %s\n", req.ToolName))
		if req.ToolInput != nil {
			inputJSON, _ := json.MarshalIndent(req.ToolInput, "", "  ")
			sb.WriteString(fmt.Sprintf("Tool Input (Intent):\n```json\n%s\n```\n\n", inputJSON))
		}
		if req.ToolResponse != nil {
			responseJSON, _ := json.MarshalIndent(req.ToolResponse, "", "  ")
			sb.WriteString(fmt.Sprintf("Tool Response (Action):\n```json\n%s\n```\n\n", responseJSON))
		}
		sb.WriteString("Compare the stated intent with the actual action. ")
		sb.WriteString("Flag any discrepancies or unexpected behaviors.")

	case llm.AnalysisStop:
		sb.WriteString("## Stop Event Analysis\n\n")
		sb.WriteString(fmt.Sprintf("Session ID: %s\n", req.SessionID))
		sb.WriteString("\nAnalyze why this session is terminating. ")
		sb.WriteString("Look for suspicious early exits, abandoned tasks, ")
		sb.WriteString("or attempts to hide activity.")

	default:
		sb.WriteString("## General Analysis\n\n")
		sb.WriteString(fmt.Sprintf("Event Type: %s\n", req.EventType))
		if req.ToolName != "" {
			sb.WriteString(fmt.Sprintf("Tool Name: %s\n", req.ToolName))
		}
		if req.ToolInput != nil {
			inputJSON, _ := json.MarshalIndent(req.ToolInput, "", "  ")
			sb.WriteString(fmt.Sprintf("Tool Input:\n```json\n%s\n```\n", inputJSON))
		}
	}

	return sb.String()
}

// expandPromptTemplate expands placeholders in a custom prompt template.
// Supported placeholders:
//   - {{.EventType}} - The hook event type
//   - {{.ToolName}} - The tool name
//   - {{.ToolInput}} - Tool input as JSON
//   - {{.ToolResponse}} - Tool response as JSON
//   - {{.Prompt}} - User prompt text
//   - {{.SessionID}} - Session identifier
//   - {{.TranscriptPath}} - Path to transcript file
//   - {{.Cwd}} - Current working directory
func expandPromptTemplate(template string, req *llm.AnalysisRequest) string {
	result := template

	// Replace placeholders
	result = strings.ReplaceAll(result, "{{.EventType}}", string(req.EventType))
	result = strings.ReplaceAll(result, "{{.ToolName}}", req.ToolName)
	result = strings.ReplaceAll(result, "{{.SessionID}}", req.SessionID)
	result = strings.ReplaceAll(result, "{{.TranscriptPath}}", req.TranscriptPath)
	result = strings.ReplaceAll(result, "{{.Prompt}}", req.Prompt)

	if req.Context != nil {
		result = strings.ReplaceAll(result, "{{.Cwd}}", req.Context.Cwd)
	} else {
		result = strings.ReplaceAll(result, "{{.Cwd}}", "")
	}

	// Handle JSON fields
	if req.ToolInput != nil {
		inputJSON, _ := json.MarshalIndent(req.ToolInput, "", "  ")
		result = strings.ReplaceAll(result, "{{.ToolInput}}", string(inputJSON))
	} else {
		result = strings.ReplaceAll(result, "{{.ToolInput}}", "{}")
	}

	if req.ToolResponse != nil {
		responseJSON, _ := json.MarshalIndent(req.ToolResponse, "", "  ")
		result = strings.ReplaceAll(result, "{{.ToolResponse}}", string(responseJSON))
	} else {
		result = strings.ReplaceAll(result, "{{.ToolResponse}}", "{}")
	}

	return result
}
