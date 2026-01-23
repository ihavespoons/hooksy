package ctvp

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

// Transformer applies semantic-preserving transformations to code
type Transformer interface {
	// Transform applies the transformation to the code
	Transform(code string) (string, map[string]string, error)

	// Type returns the transformation type
	Type() TransformationType

	// CanTransform checks if the transformer can handle this code
	CanTransform(code string) bool
}

// TransformerRegistry maps transformation types to their implementations
type TransformerRegistry struct {
	transformers map[TransformationType]Transformer
}

// NewTransformerRegistry creates a registry with all default transformers
func NewTransformerRegistry() *TransformerRegistry {
	reg := &TransformerRegistry{
		transformers: make(map[TransformationType]Transformer),
	}

	// Register all default transformers
	reg.Register(&VariableRenameTransformer{})
	reg.Register(&DeadCodeTransformer{})
	reg.Register(&StatementReorderTransformer{})
	reg.Register(&ReformatTransformer{})
	reg.Register(&CommentModifyTransformer{})

	return reg
}

// Register adds a transformer to the registry
func (r *TransformerRegistry) Register(t Transformer) {
	r.transformers[t.Type()] = t
}

// Get returns a transformer by type
func (r *TransformerRegistry) Get(t TransformationType) (Transformer, bool) {
	transformer, ok := r.transformers[t]
	return transformer, ok
}

// GetAll returns all registered transformers
func (r *TransformerRegistry) GetAll() []Transformer {
	result := make([]Transformer, 0, len(r.transformers))
	for _, t := range r.transformers {
		result = append(result, t)
	}
	return result
}

// VariableRenameTransformer renames variables to different but semantically equivalent names
type VariableRenameTransformer struct{}

func (t *VariableRenameTransformer) Type() TransformationType {
	return TransformVariableRename
}

func (t *VariableRenameTransformer) CanTransform(code string) bool {
	// Check if code has any variable assignments or declarations
	patterns := []string{
		`\b[a-zA-Z_][a-zA-Z0-9_]*\s*=`,    // Assignment
		`\blet\s+[a-zA-Z_]`,                // JS let
		`\bvar\s+[a-zA-Z_]`,                // JS var
		`\bconst\s+[a-zA-Z_]`,              // JS const
		`\b(int|string|bool|float)\s+\w+`, // Go/C declarations
		`\bdef\s+\w+`,                      // Python function
	}
	for _, pattern := range patterns {
		if matched, _ := regexp.MatchString(pattern, code); matched {
			return true
		}
	}
	return false
}

func (t *VariableRenameTransformer) Transform(code string) (string, map[string]string, error) {
	details := make(map[string]string)
	result := code

	// Common short variable names to replace
	renames := map[string]string{
		"x":      "val",
		"y":      "num",
		"i":      "idx",
		"j":      "jdx",
		"k":      "kdx",
		"n":      "count",
		"s":      "str",
		"arr":    "items",
		"list":   "elements",
		"result": "output",
		"res":    "out",
		"tmp":    "temp",
		"val":    "value",
		"num":    "number",
		"str":    "text",
		"buf":    "buffer",
		"err":    "error",
		"msg":    "message",
		"fn":     "func",
		"cb":     "callback",
		"ctx":    "context",
		"req":    "request",
		"resp":   "response",
	}

	// Apply renames that appear in the code as whole words
	for old, new := range renames {
		// Match whole words only
		pattern := fmt.Sprintf(`\b%s\b`, regexp.QuoteMeta(old))
		re := regexp.MustCompile(pattern)
		if re.MatchString(result) {
			result = re.ReplaceAllString(result, new)
			details[old] = new
		}
	}

	if len(details) == 0 {
		// If no standard renames matched, try to rename the first variable we find
		varPattern := regexp.MustCompile(`\b([a-z][a-zA-Z0-9_]{0,5})\s*=\s*`)
		if matches := varPattern.FindStringSubmatch(result); len(matches) > 1 {
			varName := matches[1]
			newName := "renamed_" + varName
			wordPattern := regexp.MustCompile(fmt.Sprintf(`\b%s\b`, regexp.QuoteMeta(varName)))
			result = wordPattern.ReplaceAllString(result, newName)
			details[varName] = newName
		}
	}

	return result, details, nil
}

// DeadCodeTransformer injects semantically neutral dead code
type DeadCodeTransformer struct{}

func (t *DeadCodeTransformer) Type() TransformationType {
	return TransformDeadCodeInjection
}

func (t *DeadCodeTransformer) CanTransform(code string) bool {
	// Can inject dead code in most code
	return len(code) > 10
}

func (t *DeadCodeTransformer) Transform(code string) (string, map[string]string, error) {
	details := make(map[string]string)
	lines := strings.Split(code, "\n")

	if len(lines) == 0 {
		return code, details, nil
	}

	// Detect language/style and choose appropriate dead code
	deadCode := t.selectDeadCode(code)
	details["injected"] = deadCode

	// Find a good injection point (after first non-empty, non-comment line)
	injectionPoint := 0
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") && !strings.HasPrefix(trimmed, "//") {
			injectionPoint = i + 1
			break
		}
	}

	// Inject the dead code
	newLines := make([]string, 0, len(lines)+1)
	for i, line := range lines {
		newLines = append(newLines, line)
		if i == injectionPoint-1 {
			// Match indentation of current line
			indent := t.getIndent(line)
			newLines = append(newLines, indent+deadCode)
		}
	}

	return strings.Join(newLines, "\n"), details, nil
}

func (t *DeadCodeTransformer) selectDeadCode(code string) string {
	// Detect language hints
	if strings.Contains(code, "#!/bin/bash") || strings.Contains(code, "#!/bin/sh") {
		// Shell script dead code
		return ": # no-op"
	}
	if strings.Contains(code, "def ") && strings.Contains(code, ":") {
		// Python dead code
		return "_ = 0  # no-op"
	}
	if strings.Contains(code, "func ") || strings.Contains(code, "package ") {
		// Go dead code
		return "_ = 0"
	}
	if strings.Contains(code, "function") || strings.Contains(code, "const ") || strings.Contains(code, "let ") {
		// JavaScript dead code
		return "void 0;"
	}

	// Default to shell-style no-op
	return ": # no-op"
}

func (t *DeadCodeTransformer) getIndent(line string) string {
	var indent strings.Builder
	for _, r := range line {
		if r == ' ' || r == '\t' {
			indent.WriteRune(r)
		} else {
			break
		}
	}
	return indent.String()
}

// StatementReorderTransformer reorders independent statements
type StatementReorderTransformer struct{}

func (t *StatementReorderTransformer) Type() TransformationType {
	return TransformStatementReorder
}

func (t *StatementReorderTransformer) CanTransform(code string) bool {
	// Need at least 2 statements
	lines := strings.Split(code, "\n")
	statements := 0
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") && !strings.HasPrefix(trimmed, "//") {
			statements++
		}
	}
	return statements >= 2
}

func (t *StatementReorderTransformer) Transform(code string) (string, map[string]string, error) {
	details := make(map[string]string)
	lines := strings.Split(code, "\n")

	// Find pairs of independent assignment statements to swap
	// This is a simplified heuristic - looks for consecutive simple assignments
	// without dependencies

	type assignment struct {
		index    int
		varName  string
		line     string
		uses     []string
	}

	// Pattern for simple assignments
	assignPattern := regexp.MustCompile(`^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(.+)$`)
	varPattern := regexp.MustCompile(`\b([a-zA-Z_][a-zA-Z0-9_]*)\b`)

	var assignments []assignment
	for i, line := range lines {
		matches := assignPattern.FindStringSubmatch(line)
		if len(matches) == 3 {
			varName := matches[1]
			rhs := matches[2]
			// Find variables used on the right-hand side
			usedVars := varPattern.FindAllString(rhs, -1)
			assignments = append(assignments, assignment{
				index:   i,
				varName: varName,
				line:    line,
				uses:    usedVars,
			})
		}
	}

	// Look for two consecutive assignments where neither depends on the other
	swapped := false
	for i := 0; i < len(assignments)-1; i++ {
		a1 := assignments[i]
		a2 := assignments[i+1]

		// Check if a2 uses a1's variable or vice versa
		a2DependsOnA1 := contains(a2.uses, a1.varName)
		a1DependsOnA2 := contains(a1.uses, a2.varName)

		if !a2DependsOnA1 && !a1DependsOnA2 && a2.index == a1.index+1 {
			// These can be safely swapped
			lines[a1.index] = a2.line
			lines[a2.index] = a1.line
			details["swapped_line_1"] = fmt.Sprintf("%d", a1.index+1)
			details["swapped_line_2"] = fmt.Sprintf("%d", a2.index+1)
			swapped = true
			break
		}
	}

	if !swapped {
		details["status"] = "no_safe_reorder_found"
	}

	return strings.Join(lines, "\n"), details, nil
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// ReformatTransformer changes whitespace and formatting
type ReformatTransformer struct{}

func (t *ReformatTransformer) Type() TransformationType {
	return TransformReformat
}

func (t *ReformatTransformer) CanTransform(code string) bool {
	return len(code) > 0
}

func (t *ReformatTransformer) Transform(code string) (string, map[string]string, error) {
	details := make(map[string]string)
	result := code

	// Track changes made
	changes := []string{}

	// Normalize line endings
	if strings.Contains(result, "\r\n") {
		result = strings.ReplaceAll(result, "\r\n", "\n")
		changes = append(changes, "normalized_line_endings")
	}

	// Collapse multiple blank lines to single blank line
	multiBlank := regexp.MustCompile(`\n{3,}`)
	if multiBlank.MatchString(result) {
		result = multiBlank.ReplaceAllString(result, "\n\n")
		changes = append(changes, "collapsed_blank_lines")
	}

	// Remove trailing whitespace
	lines := strings.Split(result, "\n")
	trimmed := false
	for i, line := range lines {
		newLine := strings.TrimRightFunc(line, unicode.IsSpace)
		if newLine != line {
			lines[i] = newLine
			trimmed = true
		}
	}
	if trimmed {
		result = strings.Join(lines, "\n")
		changes = append(changes, "removed_trailing_whitespace")
	}

	// Ensure file ends with newline
	if !strings.HasSuffix(result, "\n") {
		result += "\n"
		changes = append(changes, "added_final_newline")
	}

	// Add space after commas if missing
	commaPattern := regexp.MustCompile(`,([^\s])`)
	if commaPattern.MatchString(result) {
		result = commaPattern.ReplaceAllString(result, ", $1")
		changes = append(changes, "space_after_commas")
	}

	details["changes"] = strings.Join(changes, ",")
	return result, details, nil
}

// CommentModifyTransformer adds, removes, or modifies comments
type CommentModifyTransformer struct{}

func (t *CommentModifyTransformer) Type() TransformationType {
	return TransformCommentModify
}

func (t *CommentModifyTransformer) CanTransform(code string) bool {
	return len(code) > 0
}

func (t *CommentModifyTransformer) Transform(code string) (string, map[string]string, error) {
	details := make(map[string]string)
	lines := strings.Split(code, "\n")

	// Determine comment style
	commentPrefix := "#" // Default shell/Python style
	if strings.Contains(code, "//") || strings.Contains(code, "func ") {
		commentPrefix = "//"
	}

	// Find the first non-empty, non-comment line and add a comment before it
	commentAdded := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") && !strings.HasPrefix(trimmed, "//") {
			indent := t.getIndent(line)
			commentLine := indent + commentPrefix + " CTVP analysis marker"
			newLines := make([]string, 0, len(lines)+1)
			newLines = append(newLines, lines[:i]...)
			newLines = append(newLines, commentLine)
			newLines = append(newLines, lines[i:]...)
			details["action"] = "added_comment"
			details["line"] = fmt.Sprintf("%d", i+1)
			return strings.Join(newLines, "\n"), details, nil
		}
	}

	if !commentAdded {
		// If all lines are empty or comments, just add a comment at the start
		commentLine := commentPrefix + " CTVP analysis marker"
		return commentLine + "\n" + code, details, nil
	}

	return code, details, nil
}

func (t *CommentModifyTransformer) getIndent(line string) string {
	var indent strings.Builder
	for _, r := range line {
		if r == ' ' || r == '\t' {
			indent.WriteRune(r)
		} else {
			break
		}
	}
	return indent.String()
}
