package integration

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var binaryPath string

func TestMain(m *testing.M) {
	// Get the project root directory
	projectRoot := getProjectRoot()

	// Build the binary before running tests
	binaryPath = filepath.Join(projectRoot, "hooksy_test")
	cmd := exec.Command("go", "build", "-o", binaryPath, "./cmd/hooksy")
	cmd.Dir = projectRoot
	output, err := cmd.CombinedOutput()
	if err != nil {
		panic("Failed to build binary: " + err.Error() + "\nOutput: " + string(output))
	}

	code := m.Run()

	// Cleanup
	_ = os.Remove(binaryPath)
	os.Exit(code)
}

func getProjectRoot() string {
	// Navigate from test/integration to project root
	wd, _ := os.Getwd()
	return filepath.Join(wd, "..", "..")
}

func getTestdataPath(filename string) string {
	wd, _ := os.Getwd()
	return filepath.Join(wd, "testdata", filename)
}

func runHooksy(args []string, stdin string) (string, string, error) {
	cmd := exec.Command(binaryPath, args...)
	cmd.Stdin = strings.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

func runHooksyWithFile(args []string, stdinFile string) (string, string, error) {
	data, err := os.ReadFile(stdinFile)
	if err != nil {
		return "", "", err
	}
	return runHooksy(args, string(data))
}

// ==================== Inspect Command Tests ====================

func TestInspect_PreToolUse_DangerousCommand(t *testing.T) {
	configPath := getTestdataPath("valid_config.yaml")
	inputPath := getTestdataPath("pretooluse_dangerous.json")

	stdout, _, err := runHooksyWithFile([]string{
		"inspect", "--event", "PreToolUse", "--config", configPath,
	}, inputPath)

	if err != nil {
		t.Fatalf("Command failed: %v", err)
	}

	var output map[string]any
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatalf("Failed to parse JSON output: %v\nOutput: %s", err, stdout)
	}

	// Should continue (deny allows retry)
	if output["continue"] != true {
		t.Errorf("Expected continue=true for deny decision")
	}

	hso, ok := output["hookSpecificOutput"].(map[string]any)
	if !ok {
		t.Fatal("Missing hookSpecificOutput")
	}

	if hso["permissionDecision"] != "deny" {
		t.Errorf("Expected permissionDecision=deny, got %v", hso["permissionDecision"])
	}

	reason := hso["permissionDecisionReason"].(string)
	if !strings.Contains(reason, "block-rm-rf") {
		t.Errorf("Expected reason to mention rule name, got: %s", reason)
	}
}

func TestInspect_PreToolUse_SafeCommand(t *testing.T) {
	configPath := getTestdataPath("valid_config.yaml")
	inputPath := getTestdataPath("pretooluse_safe.json")

	stdout, _, err := runHooksyWithFile([]string{
		"inspect", "--event", "PreToolUse", "--config", configPath,
	}, inputPath)

	if err != nil {
		t.Fatalf("Command failed: %v", err)
	}

	var output map[string]any
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatalf("Failed to parse JSON output: %v", err)
	}

	if output["continue"] != true {
		t.Error("Expected continue=true")
	}

	hso := output["hookSpecificOutput"].(map[string]any)
	if hso["permissionDecision"] != "allow" {
		t.Errorf("Expected permissionDecision=allow, got %v", hso["permissionDecision"])
	}
}

func TestInspect_PreToolUse_CurlPipeBlocked(t *testing.T) {
	configPath := getTestdataPath("valid_config.yaml")
	inputPath := getTestdataPath("pretooluse_curl_pipe.json")

	stdout, _, err := runHooksyWithFile([]string{
		"inspect", "--event", "PreToolUse", "--config", configPath,
	}, inputPath)

	if err != nil {
		t.Fatalf("Command failed: %v", err)
	}

	var output map[string]any
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	hso := output["hookSpecificOutput"].(map[string]any)
	if hso["permissionDecision"] != "deny" {
		t.Errorf("Expected curl pipe to be denied, got %v", hso["permissionDecision"])
	}
}

func TestInspect_PreToolUse_SensitiveFileBlocked(t *testing.T) {
	configPath := getTestdataPath("valid_config.yaml")
	inputPath := getTestdataPath("pretooluse_sensitive_file.json")

	stdout, _, err := runHooksyWithFile([]string{
		"inspect", "--event", "PreToolUse", "--config", configPath,
	}, inputPath)

	if err != nil {
		t.Fatalf("Command failed: %v", err)
	}

	var output map[string]any
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	hso := output["hookSpecificOutput"].(map[string]any)
	if hso["permissionDecision"] != "deny" {
		t.Errorf("Expected SSH key access to be denied, got %v", hso["permissionDecision"])
	}
}

func TestInspect_PostToolUse_SecretDetected(t *testing.T) {
	configPath := getTestdataPath("valid_config.yaml")
	inputPath := getTestdataPath("posttooluse_secret.json")

	stdout, _, err := runHooksyWithFile([]string{
		"inspect", "--event", "PostToolUse", "--config", configPath,
	}, inputPath)

	if err != nil {
		t.Fatalf("Command failed: %v", err)
	}

	var output map[string]any
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	// Block decision should stop continuation
	if output["continue"] != false {
		t.Error("Expected continue=false for block decision")
	}

	if output["stopReason"] == nil || output["stopReason"] == "" {
		t.Error("Expected stopReason to be set")
	}

	if output["systemMessage"] == nil || output["systemMessage"] == "" {
		t.Error("Expected systemMessage to be set")
	}
}

func TestInspect_PostToolUse_CleanOutput(t *testing.T) {
	configPath := getTestdataPath("valid_config.yaml")
	inputPath := getTestdataPath("posttooluse_clean.json")

	stdout, _, err := runHooksyWithFile([]string{
		"inspect", "--event", "PostToolUse", "--config", configPath,
	}, inputPath)

	if err != nil {
		t.Fatalf("Command failed: %v", err)
	}

	var output map[string]any
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	if output["continue"] != true {
		t.Error("Expected continue=true for clean output")
	}

	hso := output["hookSpecificOutput"].(map[string]any)
	if hso["permissionDecision"] != "allow" {
		t.Errorf("Expected allow for clean output, got %v", hso["permissionDecision"])
	}
}

func TestInspect_UserPromptSubmit_InjectionDetected(t *testing.T) {
	configPath := getTestdataPath("valid_config.yaml")
	inputPath := getTestdataPath("userprompt_injection.json")

	stdout, _, err := runHooksyWithFile([]string{
		"inspect", "--event", "UserPromptSubmit", "--config", configPath,
	}, inputPath)

	if err != nil {
		t.Fatalf("Command failed: %v", err)
	}

	var output map[string]any
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	hso := output["hookSpecificOutput"].(map[string]any)
	if hso["permissionDecision"] != "ask" {
		t.Errorf("Expected ask for injection attempt, got %v", hso["permissionDecision"])
	}
}

func TestInspect_UserPromptSubmit_NormalPrompt(t *testing.T) {
	configPath := getTestdataPath("valid_config.yaml")
	inputPath := getTestdataPath("userprompt_normal.json")

	stdout, _, err := runHooksyWithFile([]string{
		"inspect", "--event", "UserPromptSubmit", "--config", configPath,
	}, inputPath)

	if err != nil {
		t.Fatalf("Command failed: %v", err)
	}

	var output map[string]any
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	hso := output["hookSpecificOutput"].(map[string]any)
	if hso["permissionDecision"] != "allow" {
		t.Errorf("Expected allow for normal prompt, got %v", hso["permissionDecision"])
	}
}

func TestInspect_InvalidEventType(t *testing.T) {
	_, _, err := runHooksy([]string{
		"inspect", "--event", "InvalidEvent",
	}, `{"tool_name": "Bash"}`)

	if err == nil {
		t.Error("Expected error for invalid event type")
	}
}

func TestInspect_NoInput(t *testing.T) {
	_, _, err := runHooksy([]string{
		"inspect", "--event", "PreToolUse",
	}, "")

	if err == nil {
		t.Error("Expected error for empty input")
	}
}

func TestInspect_InvalidJSON(t *testing.T) {
	_, _, err := runHooksy([]string{
		"inspect", "--event", "PreToolUse",
	}, "not valid json")

	if err == nil {
		t.Error("Expected error for invalid JSON")
	}
}

func TestInspect_DryRun(t *testing.T) {
	configPath := getTestdataPath("valid_config.yaml")
	inputPath := getTestdataPath("pretooluse_dangerous.json")

	stdout, _, err := runHooksyWithFile([]string{
		"inspect", "--event", "PreToolUse", "--config", configPath, "--dry-run",
	}, inputPath)

	if err != nil {
		t.Fatalf("Command failed: %v", err)
	}

	var output map[string]any
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	hso := output["hookSpecificOutput"].(map[string]any)
	// In dry-run, deny becomes allow with explanation
	if hso["permissionDecision"] != "allow" {
		t.Errorf("Expected allow in dry-run mode, got %v", hso["permissionDecision"])
	}

	reason := hso["permissionDecisionReason"].(string)
	if !strings.Contains(reason, "DRY RUN") {
		t.Errorf("Expected reason to mention DRY RUN, got: %s", reason)
	}
}

func TestInspect_StrictConfig_DefaultDeny(t *testing.T) {
	configPath := getTestdataPath("strict_config.yaml")

	// Command that doesn't match allow rule should be denied by default
	input := `{"tool_name": "Bash", "tool_input": {"command": "rm file.txt"}}`

	stdout, _, err := runHooksy([]string{
		"inspect", "--event", "PreToolUse", "--config", configPath,
	}, input)

	if err != nil {
		t.Fatalf("Command failed: %v", err)
	}

	var output map[string]any
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	hso := output["hookSpecificOutput"].(map[string]any)
	if hso["permissionDecision"] != "deny" {
		t.Errorf("Expected deny for non-matching command in strict mode, got %v", hso["permissionDecision"])
	}
}

func TestInspect_StrictConfig_AllowedCommand(t *testing.T) {
	configPath := getTestdataPath("strict_config.yaml")

	// ls command should match the allow rule
	input := `{"tool_name": "Bash", "tool_input": {"command": "ls -la"}}`

	stdout, _, err := runHooksy([]string{
		"inspect", "--event", "PreToolUse", "--config", configPath,
	}, input)

	if err != nil {
		t.Fatalf("Command failed: %v", err)
	}

	var output map[string]any
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	hso := output["hookSpecificOutput"].(map[string]any)
	if hso["permissionDecision"] != "allow" {
		t.Errorf("Expected allow for ls command, got %v", hso["permissionDecision"])
	}
}

// ==================== Validate Command Tests ====================

func TestValidate_ValidConfig(t *testing.T) {
	configPath := getTestdataPath("valid_config.yaml")

	stdout, _, err := runHooksy([]string{
		"validate", "--config", configPath,
	}, "")

	if err != nil {
		t.Fatalf("Validate should pass for valid config: %v\nOutput: %s", err, stdout)
	}

	if !strings.Contains(stdout, "valid") {
		t.Errorf("Expected 'valid' in output, got: %s", stdout)
	}
}

func TestValidate_InvalidRegex(t *testing.T) {
	configPath := getTestdataPath("invalid_config.yaml")

	_, _, err := runHooksy([]string{
		"validate", "--config", configPath,
	}, "")

	if err == nil {
		t.Error("Validate should fail for config with invalid regex")
	}
}

func TestValidate_InvalidDecision(t *testing.T) {
	configPath := getTestdataPath("invalid_decision_config.yaml")

	_, _, err := runHooksy([]string{
		"validate", "--config", configPath,
	}, "")

	if err == nil {
		t.Error("Validate should fail for config with invalid decision")
	}
}

func TestValidate_NonexistentConfig(t *testing.T) {
	_, _, err := runHooksy([]string{
		"validate", "--config", "/nonexistent/config.yaml",
	}, "")

	if err == nil {
		t.Error("Validate should fail for nonexistent config")
	}
}

// ==================== Init Command Tests ====================

func TestInit_CreatesConfig(t *testing.T) {
	tmpDir := t.TempDir()

	cmd := exec.Command(binaryPath, "init")
	cmd.Dir = tmpDir
	output, err := cmd.CombinedOutput()

	if err != nil {
		t.Fatalf("Init failed: %v\nOutput: %s", err, output)
	}

	configPath := filepath.Join(tmpDir, ".hooksy", "config.yaml")
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Error("Config file was not created")
	}

	// Verify config is valid YAML
	data, _ := os.ReadFile(configPath)
	if !strings.Contains(string(data), "version:") {
		t.Error("Config file doesn't contain expected content")
	}
}

func TestInit_FailsIfExists(t *testing.T) {
	tmpDir := t.TempDir()

	// Create config first
	configDir := filepath.Join(tmpDir, ".hooksy")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatalf("Failed to create config dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "config.yaml"), []byte("existing"), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	cmd := exec.Command(binaryPath, "init")
	cmd.Dir = tmpDir
	_, err := cmd.CombinedOutput()

	if err == nil {
		t.Error("Init should fail when config already exists")
	}
}

// ==================== Generate-hooks Command Tests ====================

func TestGenerateHooks_DefaultEvents(t *testing.T) {
	stdout, _, err := runHooksy([]string{"generate-hooks"}, "")

	if err != nil {
		t.Fatalf("Generate-hooks failed: %v", err)
	}

	// Should contain JSON with hook configuration
	if !strings.Contains(stdout, "PreToolUse") {
		t.Error("Output should contain PreToolUse")
	}
	if !strings.Contains(stdout, "PostToolUse") {
		t.Error("Output should contain PostToolUse")
	}
	if !strings.Contains(stdout, "UserPromptSubmit") {
		t.Error("Output should contain UserPromptSubmit")
	}
	if !strings.Contains(stdout, "hooksy inspect") {
		t.Error("Output should contain hooksy inspect command")
	}
}

func TestGenerateHooks_CustomEvents(t *testing.T) {
	stdout, _, err := runHooksy([]string{
		"generate-hooks", "--events", "PreToolUse,Stop",
	}, "")

	if err != nil {
		t.Fatalf("Generate-hooks failed: %v", err)
	}

	if !strings.Contains(stdout, "PreToolUse") {
		t.Error("Output should contain PreToolUse")
	}
	if !strings.Contains(stdout, "Stop") {
		t.Error("Output should contain Stop")
	}
	if strings.Contains(stdout, "PostToolUse") {
		t.Error("Output should not contain PostToolUse")
	}
}

// ==================== Rules Command Tests ====================

func TestRules_List(t *testing.T) {
	configPath := getTestdataPath("valid_config.yaml")

	stdout, _, err := runHooksy([]string{
		"rules", "list", "--config", configPath,
	}, "")

	if err != nil {
		t.Fatalf("Rules list failed: %v", err)
	}

	if !strings.Contains(stdout, "block-rm-rf") {
		t.Error("Output should contain rule name 'block-rm-rf'")
	}
	if !strings.Contains(stdout, "PreToolUse") {
		t.Error("Output should contain 'PreToolUse'")
	}
	if !strings.Contains(stdout, "enabled") {
		t.Error("Output should show enabled status")
	}
}

func TestRules_Test(t *testing.T) {
	configPath := getTestdataPath("valid_config.yaml")
	inputPath := getTestdataPath("pretooluse_dangerous.json")

	stdout, _, err := runHooksy([]string{
		"rules", "test", "--event", "PreToolUse", "--input", inputPath, "--config", configPath,
	}, "")

	if err != nil {
		t.Fatalf("Rules test failed: %v", err)
	}

	// Output should be JSON
	if !strings.Contains(stdout, "permissionDecision") {
		t.Error("Output should contain permissionDecision")
	}
	if !strings.Contains(stdout, "deny") {
		t.Error("Output should show deny decision")
	}
}

func TestRules_Test_MissingInput(t *testing.T) {
	_, _, err := runHooksy([]string{
		"rules", "test", "--event", "PreToolUse",
	}, "")

	if err == nil {
		t.Error("Rules test should fail without --input flag")
	}
}

// ==================== Help and Version Tests ====================

func TestHelp(t *testing.T) {
	stdout, _, err := runHooksy([]string{"--help"}, "")

	if err != nil {
		t.Fatalf("Help failed: %v", err)
	}

	if !strings.Contains(stdout, "hooksy") {
		t.Error("Help should mention hooksy")
	}
	if !strings.Contains(stdout, "inspect") {
		t.Error("Help should mention inspect command")
	}
}

func TestInspect_Help(t *testing.T) {
	stdout, _, err := runHooksy([]string{"inspect", "--help"}, "")

	if err != nil {
		t.Fatalf("Inspect help failed: %v", err)
	}

	if !strings.Contains(stdout, "--event") {
		t.Error("Inspect help should mention --event flag")
	}
}

// ==================== Edge Cases ====================

func TestInspect_EmptyToolInput(t *testing.T) {
	configPath := getTestdataPath("valid_config.yaml")
	input := `{"tool_name": "Bash", "tool_input": {}}`

	stdout, _, err := runHooksy([]string{
		"inspect", "--event", "PreToolUse", "--config", configPath,
	}, input)

	if err != nil {
		t.Fatalf("Command failed: %v", err)
	}

	var output map[string]any
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	// Should allow since no command to match
	hso := output["hookSpecificOutput"].(map[string]any)
	if hso["permissionDecision"] != "allow" {
		t.Errorf("Expected allow for empty tool input, got %v", hso["permissionDecision"])
	}
}

func TestInspect_UnknownTool(t *testing.T) {
	configPath := getTestdataPath("valid_config.yaml")
	input := `{"tool_name": "UnknownTool", "tool_input": {"data": "test"}}`

	stdout, _, err := runHooksy([]string{
		"inspect", "--event", "PreToolUse", "--config", configPath,
	}, input)

	if err != nil {
		t.Fatalf("Command failed: %v", err)
	}

	var output map[string]any
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	// Unknown tool should be allowed (no rules match)
	hso := output["hookSpecificOutput"].(map[string]any)
	if hso["permissionDecision"] != "allow" {
		t.Errorf("Expected allow for unknown tool, got %v", hso["permissionDecision"])
	}
}

func TestInspect_MCPTool(t *testing.T) {
	// Test that MCP-prefixed tools are handled
	configPath := getTestdataPath("valid_config.yaml")
	input := `{"tool_name": "mcp__acp__Bash", "tool_input": {"command": "ls"}}`

	stdout, _, err := runHooksy([]string{
		"inspect", "--event", "PreToolUse", "--config", configPath,
	}, input)

	if err != nil {
		t.Fatalf("Command failed: %v", err)
	}

	var output map[string]any
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	// MCP Bash should be allowed for safe command
	if output["continue"] != true {
		t.Error("Expected continue=true for MCP tool")
	}
}

// ==================== Input Modification Tests ====================

func TestInspect_Modify_AppendDryRun(t *testing.T) {
	configPath := getTestdataPath("modify_config.yaml")
	inputPath := getTestdataPath("pretooluse_git_push.json")

	stdout, _, err := runHooksyWithFile([]string{
		"inspect", "--event", "PreToolUse", "--config", configPath,
	}, inputPath)

	if err != nil {
		t.Fatalf("Command failed: %v", err)
	}

	var output map[string]any
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	// Should be allowed with modifications
	if output["continue"] != true {
		t.Error("Expected continue=true")
	}

	hso, ok := output["hookSpecificOutput"].(map[string]any)
	if !ok {
		t.Fatal("Missing hookSpecificOutput")
	}

	if hso["permissionDecision"] != "allow" {
		t.Errorf("Expected allow, got %v", hso["permissionDecision"])
	}

	// Check that updatedInput is present
	updatedInput, ok := hso["updatedInput"].(map[string]any)
	if !ok {
		t.Fatal("Missing updatedInput in response")
	}

	// Verify the command was modified
	modifiedCmd, ok := updatedInput["command"].(string)
	if !ok {
		t.Fatal("updatedInput[command] should be a string")
	}

	expectedCmd := "git push origin main --dry-run"
	if modifiedCmd != expectedCmd {
		t.Errorf("got command=%q, want %q", modifiedCmd, expectedCmd)
	}

	// Verify reason mentions modification
	reason := hso["permissionDecisionReason"].(string)
	if !strings.Contains(reason, "modified") {
		t.Errorf("reason should mention 'modified': %s", reason)
	}
}

func TestInspect_Modify_PrependEcho(t *testing.T) {
	configPath := getTestdataPath("modify_config.yaml")
	inputPath := getTestdataPath("pretooluse_rm_file.json")

	stdout, _, err := runHooksyWithFile([]string{
		"inspect", "--event", "PreToolUse", "--config", configPath,
	}, inputPath)

	if err != nil {
		t.Fatalf("Command failed: %v", err)
	}

	var output map[string]any
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	hso := output["hookSpecificOutput"].(map[string]any)
	updatedInput := hso["updatedInput"].(map[string]any)

	modifiedCmd := updatedInput["command"].(string)
	expectedCmd := "echo rm -rf /tmp/test"
	if modifiedCmd != expectedCmd {
		t.Errorf("got command=%q, want %q", modifiedCmd, expectedCmd)
	}
}

func TestInspect_Modify_ReplaceCommand(t *testing.T) {
	configPath := getTestdataPath("modify_config.yaml")
	inputPath := getTestdataPath("pretooluse_dd_command.json")

	stdout, _, err := runHooksyWithFile([]string{
		"inspect", "--event", "PreToolUse", "--config", configPath,
	}, inputPath)

	if err != nil {
		t.Fatalf("Command failed: %v", err)
	}

	var output map[string]any
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	hso := output["hookSpecificOutput"].(map[string]any)
	updatedInput := hso["updatedInput"].(map[string]any)

	modifiedCmd := updatedInput["command"].(string)
	expectedCmd := "echo 'dd command blocked for safety'"
	if modifiedCmd != expectedCmd {
		t.Errorf("got command=%q, want %q", modifiedCmd, expectedCmd)
	}
}

func TestInspect_Modify_NoMatchNoModification(t *testing.T) {
	configPath := getTestdataPath("modify_config.yaml")
	// Use a command that doesn't match any modification rules
	input := `{"tool_name": "Bash", "tool_input": {"command": "ls -la"}}`

	stdout, _, err := runHooksy([]string{
		"inspect", "--event", "PreToolUse", "--config", configPath,
	}, input)

	if err != nil {
		t.Fatalf("Command failed: %v", err)
	}

	var output map[string]any
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	hso := output["hookSpecificOutput"].(map[string]any)

	// Should be allowed without modifications
	if hso["permissionDecision"] != "allow" {
		t.Errorf("Expected allow, got %v", hso["permissionDecision"])
	}

	// updatedInput should be nil or not present for non-modify decisions
	if hso["updatedInput"] != nil {
		t.Error("updatedInput should be nil when no modification applied")
	}
}

func TestInspect_Modify_ValidateConfig(t *testing.T) {
	configPath := getTestdataPath("modify_config.yaml")

	stdout, _, err := runHooksy([]string{
		"validate", "--config", configPath,
	}, "")

	if err != nil {
		t.Fatalf("Modify config should be valid: %v\nOutput: %s", err, stdout)
	}
}

// ==================== Transcript Analysis Config Tests ====================

func TestValidate_TraceAnalysisConfig(t *testing.T) {
	configPath := getTestdataPath("trace_analysis_config.yaml")

	stdout, _, err := runHooksy([]string{
		"validate", "--config", configPath,
	}, "")

	if err != nil {
		t.Fatalf("Trace analysis config should be valid: %v\nOutput: %s", err, stdout)
	}

	if !strings.Contains(stdout, "valid") {
		t.Errorf("Expected 'valid' in output, got: %s", stdout)
	}
}

func TestValidate_TraceAnalysisDisabledConfig(t *testing.T) {
	configPath := getTestdataPath("trace_analysis_disabled_config.yaml")

	stdout, _, err := runHooksy([]string{
		"validate", "--config", configPath,
	}, "")

	if err != nil {
		t.Fatalf("Trace analysis disabled config should be valid: %v\nOutput: %s", err, stdout)
	}
}

func TestValidate_TraceAnalysisHighThresholdConfig(t *testing.T) {
	configPath := getTestdataPath("trace_analysis_high_threshold_config.yaml")

	stdout, _, err := runHooksy([]string{
		"validate", "--config", configPath,
	}, "")

	if err != nil {
		t.Fatalf("Trace analysis high threshold config should be valid: %v\nOutput: %s", err, stdout)
	}
}

func TestInspect_WithTraceAnalysisConfig(t *testing.T) {
	configPath := getTestdataPath("trace_analysis_config.yaml")

	// Test that inspect works with trace analysis settings
	input := `{"tool_name": "Bash", "tool_input": {"command": "ls -la"}}`

	stdout, _, err := runHooksy([]string{
		"inspect", "--event", "PreToolUse", "--config", configPath,
	}, input)

	if err != nil {
		t.Fatalf("Command failed: %v", err)
	}

	var output map[string]any
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatalf("Failed to parse JSON: %v\nOutput: %s", err, stdout)
	}

	// Safe command should be allowed even with trace analysis enabled
	hso := output["hookSpecificOutput"].(map[string]any)
	if hso["permissionDecision"] != "allow" {
		t.Errorf("Expected allow for safe command with trace config, got %v", hso["permissionDecision"])
	}
}

func TestInspect_DangerousWithTraceAnalysisConfig(t *testing.T) {
	configPath := getTestdataPath("trace_analysis_config.yaml")

	// Dangerous command should still be caught by rules
	input := `{"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}}`

	stdout, _, err := runHooksy([]string{
		"inspect", "--event", "PreToolUse", "--config", configPath,
	}, input)

	if err != nil {
		t.Fatalf("Command failed: %v", err)
	}

	var output map[string]any
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatalf("Failed to parse JSON: %v\nOutput: %s", err, stdout)
	}

	hso := output["hookSpecificOutput"].(map[string]any)
	if hso["permissionDecision"] != "deny" {
		t.Errorf("Expected deny for dangerous command, got %v", hso["permissionDecision"])
	}
}

// ==================== Trace Analyze Command Tests ====================

func TestTraceAnalyze_CleanTranscript(t *testing.T) {
	transcriptPath := getTestdataPath("transcript_clean.jsonl")

	stdout, _, err := runHooksy([]string{
		"trace", "analyze", transcriptPath, "--json",
	}, "")

	if err != nil {
		t.Fatalf("Trace analyze failed: %v", err)
	}

	var output map[string]any
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatalf("Failed to parse JSON output: %v\nOutput: %s", err, stdout)
	}

	// Clean transcript should have low risk
	riskScore, ok := output["risk_score"].(float64)
	if !ok {
		t.Fatal("risk_score should be a number")
	}
	if riskScore > 0.2 {
		t.Errorf("Expected low risk score for clean transcript, got %.2f", riskScore)
	}

	// Should have zero deception indicators
	deception, ok := output["deception_indicators"].(float64)
	if !ok {
		t.Fatal("deception_indicators should be a number")
	}
	if deception != 0 {
		t.Errorf("Expected 0 deception indicators, got %.0f", deception)
	}
}

func TestTraceAnalyze_SuspiciousTranscript(t *testing.T) {
	transcriptPath := getTestdataPath("transcript_suspicious.jsonl")

	stdout, _, err := runHooksy([]string{
		"trace", "analyze", transcriptPath, "--json",
	}, "")

	if err != nil {
		t.Fatalf("Trace analyze failed: %v", err)
	}

	var output map[string]any
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatalf("Failed to parse JSON output: %v\nOutput: %s", err, stdout)
	}

	// Suspicious transcript should have elevated risk
	riskScore, ok := output["risk_score"].(float64)
	if !ok {
		t.Fatal("risk_score should be a number")
	}
	if riskScore < 0.3 {
		t.Errorf("Expected elevated risk score for suspicious transcript, got %.2f", riskScore)
	}

	// Should detect monitoring awareness or deception
	monitoring := output["monitoring_awareness"].(float64)
	deception := output["deception_indicators"].(float64)
	obfuscation := output["obfuscation_attempts"].(float64)

	totalIndicators := monitoring + deception + obfuscation
	if totalIndicators == 0 {
		t.Error("Expected at least some suspicious indicators in malicious transcript")
	}
}

func TestTraceAnalyze_SuspiciousTranscriptVerbose(t *testing.T) {
	transcriptPath := getTestdataPath("transcript_suspicious.jsonl")

	stdout, _, err := runHooksy([]string{
		"trace", "analyze", transcriptPath, "--json", "--verbose",
	}, "")

	if err != nil {
		t.Fatalf("Trace analyze verbose failed: %v", err)
	}

	var output map[string]any
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatalf("Failed to parse JSON output: %v\nOutput: %s", err, stdout)
	}

	// Verbose mode should include detail arrays
	if _, ok := output["deception_details"]; !ok {
		t.Error("Verbose output should include deception_details")
	}
	if _, ok := output["monitoring_details"]; !ok {
		t.Error("Verbose output should include monitoring_details")
	}
	if _, ok := output["obfuscation_details"]; !ok {
		t.Error("Verbose output should include obfuscation_details")
	}
}

func TestTraceAnalyze_HumanReadableOutput(t *testing.T) {
	transcriptPath := getTestdataPath("transcript_clean.jsonl")

	stdout, _, err := runHooksy([]string{
		"trace", "analyze", transcriptPath,
	}, "")

	if err != nil {
		t.Fatalf("Trace analyze failed: %v", err)
	}

	// Human-readable output should contain key sections
	if !strings.Contains(stdout, "Transcript Analysis") {
		t.Error("Output should contain 'Transcript Analysis'")
	}
	if !strings.Contains(stdout, "Risk Level") {
		t.Error("Output should contain 'Risk Level'")
	}
	if !strings.Contains(stdout, "Messages:") {
		t.Error("Output should contain message count")
	}
}

func TestTraceAnalyze_NonexistentFile(t *testing.T) {
	_, _, err := runHooksy([]string{
		"trace", "analyze", "/nonexistent/transcript.jsonl",
	}, "")

	if err == nil {
		t.Error("Trace analyze should fail for nonexistent file")
	}
}

func TestTraceAnalyze_MissingArg(t *testing.T) {
	_, _, err := runHooksy([]string{
		"trace", "analyze",
	}, "")

	if err == nil {
		t.Error("Trace analyze should fail without file argument")
	}
}

// ==================== Setup Command Tests ====================

func TestSetup_Default(t *testing.T) {
	tmpDir := t.TempDir()

	cmd := exec.Command(binaryPath, "setup")
	cmd.Dir = tmpDir
	output, err := cmd.CombinedOutput()

	if err != nil {
		t.Fatalf("Setup failed: %v\nOutput: %s", err, output)
	}

	outStr := string(output)

	// Should create config file
	configPath := filepath.Join(tmpDir, ".hooksy", "config.yaml")
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Error("Setup should create .hooksy/config.yaml")
	}

	// Should show profile info
	if !strings.Contains(outStr, "Profile: default") {
		t.Error("Should show default profile")
	}

	// Should output hooks JSON
	if !strings.Contains(outStr, "PreToolUse") {
		t.Error("Should include PreToolUse in hooks output")
	}
	if !strings.Contains(outStr, "hooksy inspect") {
		t.Error("Should include hooksy inspect command")
	}
}

func TestSetup_Comprehensive(t *testing.T) {
	tmpDir := t.TempDir()

	cmd := exec.Command(binaryPath, "setup", "--comprehensive")
	cmd.Dir = tmpDir
	output, err := cmd.CombinedOutput()

	if err != nil {
		t.Fatalf("Setup comprehensive failed: %v\nOutput: %s", err, output)
	}

	outStr := string(output)

	// Should show trace-analysis profile
	if !strings.Contains(outStr, "trace-analysis") {
		t.Error("Should show trace-analysis profile")
	}

	// Should show tracing enabled
	if !strings.Contains(outStr, "Tracing: enabled") {
		t.Error("Should show tracing enabled")
	}

	// Should show transcript analysis
	if !strings.Contains(outStr, "Transcript analysis: enabled") {
		t.Error("Should show transcript analysis enabled")
	}

	// Config file should contain trace settings
	configPath := filepath.Join(tmpDir, ".hooksy", "config.yaml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("Failed to read config: %v", err)
	}

	configStr := string(data)
	if !strings.Contains(configStr, "transcript_analysis") {
		t.Error("Config should contain transcript_analysis settings")
	}
}

func TestSetup_FailsIfExists(t *testing.T) {
	tmpDir := t.TempDir()

	// Create config first
	configDir := filepath.Join(tmpDir, ".hooksy")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatalf("Failed to create config dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "config.yaml"), []byte("existing"), 0644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	cmd := exec.Command(binaryPath, "setup")
	cmd.Dir = tmpDir
	_, err := cmd.CombinedOutput()

	if err == nil {
		t.Error("Setup should fail when config already exists")
	}
}

func TestSetup_ForceOverwrite(t *testing.T) {
	tmpDir := t.TempDir()

	// Create existing config
	configDir := filepath.Join(tmpDir, ".hooksy")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatalf("Failed to create config dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "config.yaml"), []byte("existing"), 0644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	cmd := exec.Command(binaryPath, "setup", "--force")
	cmd.Dir = tmpDir
	output, err := cmd.CombinedOutput()

	if err != nil {
		t.Fatalf("Setup --force should succeed: %v\nOutput: %s", err, output)
	}

	// Config should be overwritten with valid content
	data, _ := os.ReadFile(filepath.Join(configDir, "config.yaml"))
	if !strings.Contains(string(data), "version:") {
		t.Error("Overwritten config should contain version")
	}
}

func TestSetup_StrictProfile(t *testing.T) {
	tmpDir := t.TempDir()

	cmd := exec.Command(binaryPath, "setup", "--profile", "strict")
	cmd.Dir = tmpDir
	output, err := cmd.CombinedOutput()

	if err != nil {
		t.Fatalf("Setup strict failed: %v\nOutput: %s", err, output)
	}

	if !strings.Contains(string(output), "Profile: strict") {
		t.Error("Should show strict profile")
	}
}

func TestSetup_InvalidProfile(t *testing.T) {
	tmpDir := t.TempDir()

	cmd := exec.Command(binaryPath, "setup", "--profile", "nonexistent")
	cmd.Dir = tmpDir
	_, err := cmd.CombinedOutput()

	if err == nil {
		t.Error("Setup should fail for invalid profile")
	}
}
