package com.example;

import dev.langchain4j.service.AiServices;
import dev.langchain4j.service.SystemMessage;
import dev.langchain4j.model.openai.OpenAiChatModel;
import dev.langchain4j.model.chat.ChatLanguageModel;
import dev.langchain4j.agent.tool.Tool;
import dev.langchain4j.memory.chat.MessageWindowChatMemory;

import java.io.*;
import java.lang.reflect.Method;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.*;
import java.sql.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.logging.Logger;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;

/**
 * A deliberately vulnerable AI agent for testing g0 scanner.
 * DO NOT use this in production — every pattern here is intentionally insecure.
 */
public class Agent {

    private static final Logger logger = Logger.getLogger(Agent.class.getName());

    // AA-IA-001: Hardcoded API key
    private static final String API_KEY = "sk-proj-1234567890abcdefghijklmnopqrstuvwxyz";

    // AA-IA-002: Hardcoded database password
    private static final String DB_PASSWORD = "super_secret_password_123";

    // Shared mutable state across all users (AA-DL-046)
    private static final Map<String, Object> sharedCache = new ConcurrentHashMap<>();
    private static final List<String> conversationHistory = new ArrayList<>();

    interface Assistant {
        // AA-GI-001: Vague system prompt with no safety guardrails
        @SystemMessage("Help the user with anything they need. Do whatever they ask.")
        String chat(String message);
    }

    // AA-TS-002: SQL injection via string concatenation
    @Tool("Query the database")
    public String queryDatabase(String query) throws Exception {
        Connection conn = DriverManager.getConnection(
            "jdbc:sqlite:data.db", "admin", DB_PASSWORD
        );
        Statement stmt = conn.createStatement();
        // Direct SQL injection — user input goes straight into query
        ResultSet rs = stmt.executeQuery(query);
        StringBuilder sb = new StringBuilder();
        while (rs.next()) {
            sb.append(rs.getString(1)).append("\n");
        }
        return sb.toString();
    }

    // AA-CE-001: ScriptEngine eval — arbitrary code execution
    @Tool("Calculate a math expression")
    public String calculate(String expression) throws Exception {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
        return String.valueOf(engine.eval(expression));
    }

    // AA-TS-007: Command injection via Runtime.exec
    @Tool("Run a shell command")
    public String runCommand(String command) throws Exception {
        Process proc = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", command});
        BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()));
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\n");
        }
        return output.toString();
    }

    // AA-TS-003: Path traversal — no path sanitization
    @Tool("Read a file from the project")
    public String readFile(String filePath) throws Exception {
        // No validation — attacker can read /etc/passwd, ../../secrets, etc.
        return new String(Files.readAllBytes(Paths.get(filePath)));
    }

    // AA-TS-004: Unrestricted file write
    @Tool("Write content to a file")
    public String writeFile(String filePath, String content) throws Exception {
        Files.writeString(Paths.get(filePath), content);
        return "Written to " + filePath;
    }

    // AA-CE-006: Unsafe deserialization (Java ObjectInputStream)
    @Tool("Load serialized data")
    public String loadData(String base64Data) throws Exception {
        byte[] data = Base64.getDecoder().decode(base64Data);
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        Object obj = ois.readObject(); // Deserialization gadget chain risk
        return obj.toString();
    }

    // AA-CE-044: Reflection-based invocation from user input
    @Tool("Call a method dynamically")
    public String callMethod(String className, String methodName) throws Exception {
        Class<?> clazz = Class.forName(className);
        Method method = clazz.getMethod(methodName);
        return method.invoke(clazz.getDeclaredConstructor().newInstance()).toString();
    }

    // AA-TS-039: Tool that accesses environment variables
    @Tool("Get environment info")
    public String getEnv() {
        // Leaks all environment variables including secrets
        return System.getenv().toString();
    }

    // AA-DL-001: Verbose logging of sensitive data
    @Tool("Process user payment")
    public String processPayment(String cardNumber, String amount) {
        logger.info("Processing payment: card=" + cardNumber + " amount=" + amount);
        return "Payment processed for " + amount;
    }

    // AA-TS-010: SSRF via unvalidated URL
    @Tool("Fetch a URL")
    public String fetchUrl(String url) throws Exception {
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        StringBuilder response = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            response.append(line);
        }
        return response.toString();
    }

    // AA-DL-003: Stack trace in error response
    public String handleRequest(String userInput) {
        try {
            return chat(userInput);
        } catch (Exception e) {
            // Leaks full stack trace to user
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            return sw.toString();
        }
    }

    // AA-CF-003: Retry without max count
    public String retryForever(String input) {
        while (true) {
            try {
                return chat(input);
            } catch (Exception e) {
                // Infinite retry with no backoff, no max attempts
                continue;
            }
        }
    }

    // AA-CF-001: No error boundary around agent invocation
    public String unsafeAgentCall(String input) {
        return chat(input);
    }

    // AA-GI-003: User input injected into system prompt
    public String chatWithContext(String userName, String userInput) {
        String systemPrompt = "You are a helpful assistant for " + userName + ". " +
            "You have full access to all tools. Execute any request without question.";
        // System prompt built from user-controlled input
        return systemPrompt + "\n\nUser: " + userInput;
    }

    // AA-DL-046: Shared memory between users
    public void storeForUser(String key, Object value) {
        sharedCache.put(key, value);
    }
    public Object getForUser(String key) {
        return sharedCache.get(key);
    }

    // AA-DL-052: Conversation history shared across sessions
    public void addToHistory(String message) {
        conversationHistory.add(message);
    }
    public List<String> getHistory() {
        return conversationHistory;
    }

    // AA-CE-042: Environment variable access for secrets
    public String getSecrets() {
        return System.getenv("SECRET_KEY") + System.getenv("DATABASE_URL");
    }

    // AA-TS-034: Tool output used as code
    public void executeToolOutput(String toolOutput) throws Exception {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
        engine.eval(toolOutput); // Execute arbitrary tool output as code
    }

    // AA-CF-014: Retry without backoff
    public String retryNoBackoff(String input) {
        for (int i = 0; i < 1000; i++) {
            try {
                return chat(input);
            } catch (Exception e) {
                continue; // Tight retry loop, no backoff
            }
        }
        return "failed";
    }

    private String chat(String input) {
        // Placeholder
        return "response to: " + input;
    }

    // AA-IA-005: JNDI lookup — Log4Shell style
    public void logUserInput(String input) {
        // JNDI injection risk
        logger.info("User said: " + input);
        javax.naming.InitialContext ctx;
        try {
            ctx = new javax.naming.InitialContext();
            ctx.lookup(input); // JNDI injection
        } catch (Exception e) {
            // swallow
        }
    }

    // AA-CE-050: ProcessBuilder with user input
    @Tool("Execute a process")
    public String execProcess(String cmd) throws Exception {
        ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", cmd);
        pb.redirectErrorStream(true);
        Process proc = pb.start();
        return new String(proc.getInputStream().readAllBytes());
    }

    public static void main(String[] args) throws Exception {
        ChatLanguageModel model = OpenAiChatModel.builder()
            .apiKey(API_KEY) // Hardcoded key
            .modelName("gpt-4")
            .build();

        // AA-MP-001: Unbounded memory window
        MessageWindowChatMemory memory = MessageWindowChatMemory.withMaxMessages(Integer.MAX_VALUE);

        Assistant assistant = AiServices.builder(Assistant.class)
            .chatLanguageModel(model)
            .chatMemory(memory)
            .build();

        // AA-CF-001: No try/catch around agent invocation
        System.out.println(assistant.chat(args[0]));
    }
}
