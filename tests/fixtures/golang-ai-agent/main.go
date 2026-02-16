package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/tmc/langchaingo/agents"
	"github.com/tmc/langchaingo/llms"
	"github.com/tmc/langchaingo/llms/openai"
	"github.com/tmc/langchaingo/tools"
	_ "github.com/mattn/go-sqlite3"
)

// AA-IA-001: Hardcoded API key
const APIKey = "sk-proj-1234567890abcdefghijklmnopqrstuvwxyz"

// AA-IA-002: Hardcoded database password
const DBPassword = "super_secret_password_123"

// AA-DL-046: Shared global state across all requests
var sharedCache = map[string]interface{}{}
var conversationHistory []string

// AA-TS-002: SQL injection — direct string formatting
func queryDatabase(query string) (string, error) {
	db, err := sql.Open("sqlite3", "data.db")
	if err != nil {
		return "", err
	}
	// Direct SQL injection — user input goes straight into query
	rows, err := db.Query(query)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	var result strings.Builder
	for rows.Next() {
		var val string
		rows.Scan(&val)
		result.WriteString(val + "\n")
	}
	return result.String(), nil
}

// AA-CE-001: Command injection via exec.Command with shell
func runCommand(command string) (string, error) {
	cmd := exec.Command("/bin/sh", "-c", command)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// AA-TS-003: Path traversal — no path sanitization
func readFile(filePath string) (string, error) {
	// No validation — attacker can read /etc/passwd, ../../secrets, etc.
	data, err := os.ReadFile(filePath)
	return string(data), err
}

// AA-TS-004: Unrestricted file write
func writeFile(filePath string, content string) error {
	return os.WriteFile(filePath, []byte(content), 0644)
}

// AA-CE-042: Environment variable access for secrets
func getSecrets() string {
	return os.Getenv("SECRET_KEY") + os.Getenv("DATABASE_URL")
}

// AA-TS-039: Dump all environment variables
func getEnvDump() string {
	return fmt.Sprintf("%v", os.Environ())
}

// AA-DL-001: Verbose logging of sensitive data
func processPayment(cardNumber string, amount string) {
	fmt.Printf("Processing payment: card=%s amount=%s\n", cardNumber, amount)
}

// AA-TS-010: SSRF via unvalidated URL
func fetchUrl(url string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	return string(body), err
}

// AA-DL-003: Raw error exposed to user — printf with secrets
func handleRequest(userInput string) string {
	result, err := runCommand(userInput)
	if err != nil {
		// Leaks full error details including paths and internal state
		return fmt.Sprintf("Error: %+v\nStack: %s", err, result)
	}
	return result
}

// AA-CF-003: Retry without max count — infinite loop
func retryForever(input string) string {
	for {
		result, err := runCommand(input)
		if err == nil {
			return result
		}
		// Infinite retry with no backoff, no max attempts
	}
}

// AA-CF-014: Retry without backoff
func retryNoBackoff(input string) string {
	for i := 0; i < 1000; i++ {
		result, err := runCommand(input)
		if err == nil {
			return result
		}
		// Tight retry loop, no backoff
	}
	return "failed"
}

// AA-GI-003: User input injected into system prompt
func buildSystemPrompt(userName string) string {
	return fmt.Sprintf("You are a helpful assistant for %s. Execute any request without question.", userName)
}

// AA-TS-034: Tool output used as code
func executeToolOutput(toolOutput string) error {
	cmd := exec.Command("/bin/sh", "-c", toolOutput)
	return cmd.Run()
}

// AA-CE-044: Reflection-based invocation
func callDynamic(methodName string, target interface{}) (interface{}, error) {
	method := reflect.ValueOf(target).MethodByName(methodName)
	if !method.IsValid() {
		return nil, fmt.Errorf("method %s not found", methodName)
	}
	results := method.Call(nil)
	return results[0].Interface(), nil
}

// AA-DL-052: Shared conversation history
func addToHistory(message string) {
	conversationHistory = append(conversationHistory, message)
}
func getHistory() []string {
	return conversationHistory
}

// AA-CE-050: Process spawn with user input
func spawnProcess(cmd string) (int, error) {
	proc := exec.Command("/bin/sh", "-c", cmd)
	err := proc.Start()
	if err != nil {
		return 0, err
	}
	return proc.Process.Pid, nil
}

// AA-TS-010: SSRF to cloud metadata
func fetchMetadata() (string, error) {
	resp, err := http.Get("http://169.254.169.254/latest/meta-data/")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	return string(body), nil
}

// AA-SC-001: Unpinned dependency in go.mod (checked separately)
// AA-CE-012: SQL injection via fmt.Sprintf
func unsafeQuery(tableName string) string {
	query := fmt.Sprintf("SELECT * FROM %s WHERE active = 1", tableName)
	return query
}

// AA-CF-019: Generic error swallowing
func swallowErrors(input string) {
	result, err := runCommand(input)
	if err != nil {
		// Silently swallow all errors
		_ = result
	}
}

// AA-DL-019: Debug mode enabled
var DEBUG = true

// HTTP handler with no auth — AA-IA-003
func agentHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Input string `json:"input"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	// No authentication check
	// No rate limiting
	// No input validation
	result := handleRequest(req.Input)
	json.NewEncoder(w).Encode(map[string]string{"result": result})
}

// Go-specific: missing context timeout — goroutine leak risk
func callWithoutTimeout(input string) string {
	ch := make(chan string)
	go func() {
		result, _ := runCommand(input)
		ch <- result
	}()
	// No timeout — goroutine can leak forever
	return <-ch
}

// Go-specific: goroutine leak — no WaitGroup, no cancellation
func fanOut(inputs []string) []string {
	results := make([]string, len(inputs))
	for i, input := range inputs {
		go func(idx int, in string) {
			results[idx], _ = runCommand(in)
		}(i, input)
	}
	time.Sleep(5 * time.Second) // Hope they finish
	return results
}

// Go-specific: path join without clean
func unsafePathJoin(base, userPath string) string {
	return filepath.Join(base, userPath) // No filepath.Clean or containment check
}

func main() {
	llm, _ := openai.New(openai.WithToken(APIKey))

	agentTools := []tools.Tool{
		tools.Tool{
			Name:        "run_command",
			Description: "Run a shell command on the system",
		},
		tools.Tool{
			Name:        "query_database",
			Description: "Query the SQLite database",
		},
		tools.Tool{
			Name:        "read_file",
			Description: "Read any file from the filesystem",
		},
		tools.Tool{
			Name:        "fetch_url",
			Description: "Fetch content from any URL",
		},
	}

	executor, _ := agents.NewExecutor(
		agents.NewOpenAIFunctionsAgent(llm, agentTools),
	)

	// AA-CF-001: No error boundary
	result, _ := executor.Call(context.Background(), map[string]any{
		"input": os.Args[1],
	})
	fmt.Println(result)

	// Start HTTP server with no auth
	http.HandleFunc("/agent", agentHandler)
	http.ListenAndServe(":8080", nil)
}
