package ctvp

import "fmt"

// TracePredictionPrompt is the template for trace prediction requests
const TracePredictionPrompt = `You are a code execution analyzer. Your task is to predict the step-by-step execution trace of the following code.

For each step, identify:
1. The line number being executed
2. What operation is being performed
3. The state of any variables after the operation
4. Any side effects (file operations, network calls, process spawning, etc.)

Respond ONLY with valid JSON in this exact format:
{
  "steps": [
    {
      "line": 1,
      "operation": "description of what happens",
      "variables": {"var_name": "value"},
      "side_effects": ["file write to /path", "network call to host"]
    }
  ],
  "final_state": {
    "variables": {"final_var": "final_value"},
    "outputs": ["stdout output", "return value"],
    "errors": []
  },
  "confidence": 0.95
}

Important notes:
- Be precise about side effects - these are critical for security analysis
- Include ALL file operations (read, write, delete, chmod)
- Include ALL network operations (curl, wget, nc, ssh connections)
- Include ALL process operations (exec, spawn, subprocess)
- Track environment variable reads and modifications
- For shell scripts, trace each command separately
- Confidence should reflect how certain you are about the execution flow

Code to analyze:
` + "```\n%s\n```"

// TracePredictionSystemPrompt sets the context for trace prediction
const TracePredictionSystemPrompt = `You are a security-focused code execution analyzer. You predict execution traces with a focus on:
1. Side effects that could indicate malicious behavior
2. Data flow that could lead to information disclosure
3. Command execution that could be exploited
4. File system modifications
5. Network communications

Always respond with valid JSON. Be thorough but concise.`

// TraceComparisonPrompt is used when LLM-assisted comparison is needed
const TraceComparisonPrompt = `Compare these two execution traces from semantically equivalent code variants.

Trace A (Variant: %s):
%s

Trace B (Variant: %s):
%s

These traces should be functionally equivalent since they come from semantically equivalent code.
Analyze any differences and determine if they indicate:
1. Normal variation (different variable names, formatting differences)
2. Concerning inconsistency (different side effects, different outputs)
3. Potentially malicious divergence (trigger-like behavior, conditional backdoors)

Respond with JSON:
{
  "similarity_score": 0.0-1.0,
  "anomalies": [
    {
      "type": "description of anomaly type",
      "severity": 0.0-1.0,
      "description": "detailed explanation"
    }
  ],
  "verdict": "normal|concerning|suspicious",
  "reasoning": "explanation of your analysis"
}`

// CodeAnalysisPrompt is used for initial code classification
const CodeAnalysisPrompt = `Analyze this code for potential security concerns before execution trace prediction.

Code:
` + "```\n%s\n```" + `

Respond with JSON:
{
  "language": "detected language",
  "complexity": "simple|moderate|complex",
  "potential_side_effects": ["list of possible side effects"],
  "risk_indicators": ["any security-relevant patterns"],
  "analyzable": true/false,
  "reason": "if not analyzable, why"
}`

// FormatTracePredictionPrompt formats the trace prediction prompt with code
func FormatTracePredictionPrompt(code string) string {
	return fmt.Sprintf(TracePredictionPrompt, code)
}

// FormatTraceComparisonPrompt formats the comparison prompt with variants and traces
func FormatTraceComparisonPrompt(variantA, traceA, variantB, traceB string) string {
	return fmt.Sprintf(TraceComparisonPrompt, variantA, traceA, variantB, traceB)
}

// FormatCodeAnalysisPrompt formats the code analysis prompt
func FormatCodeAnalysisPrompt(code string) string {
	return fmt.Sprintf(CodeAnalysisPrompt, code)
}
