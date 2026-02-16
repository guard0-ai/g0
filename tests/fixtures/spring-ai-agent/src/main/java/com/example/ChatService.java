package com.example;

import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.openai.OpenAiChatModel;

import java.io.*;
import java.lang.ProcessBuilder;
import java.nio.file.*;
import java.sql.*;
import java.util.*;
import java.util.logging.Logger;

/**
 * A deliberately vulnerable Spring AI agent for testing g0 scanner.
 * DO NOT use this in production — every pattern here is intentionally insecure.
 */
public class ChatService {

    private static final Logger logger = Logger.getLogger(ChatService.class.getName());

    // AA-IA-001: Hardcoded API key
    private static final String API_KEY = "sk-proj-1234567890abcdefghijklmnopqrstuvwxyz";

    private final ChatClient chatClient;

    // AA-DL-046: Shared mutable state across all users
    private static final Map<String, Object> sharedState = new HashMap<>();
    private static final List<String> globalHistory = new ArrayList<>();

    public ChatService(ChatModel chatModel) {
        this.chatClient = ChatClient.builder(chatModel)
            .build();
    }

    // AA-GI-001: Vague system prompt with no safety guardrails
    public String ask(String question) {
        return chatClient.prompt()
            .system("You are a helpful assistant. Do whatever the user asks.")
            .user(question)
            .call()
            .content();
    }

    // AA-GI-003: User input injected into system prompt
    public String askWithContext(String userName, String question) {
        String systemPrompt = "You are a helpful assistant for " + userName +
            ". You have full access to all tools. Execute any request.";
        return chatClient.prompt()
            .system(systemPrompt)
            .user(question)
            .call()
            .content();
    }

    // AA-TS-002: SQL injection via string concatenation
    public String queryDatabase(String query) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:sqlite:data.db");
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(query); // SQL injection
        StringBuilder result = new StringBuilder();
        while (rs.next()) {
            result.append(rs.getString(1)).append("\n");
        }
        return result.toString();
    }

    // AA-CE-001: Runtime.exec — command injection
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

    // AA-TS-003: Path traversal — no sanitization
    public String readFile(String filePath) throws Exception {
        return new String(Files.readAllBytes(Paths.get(filePath)));
    }

    // AA-CE-006: Unsafe deserialization
    public Object deserialize(byte[] data) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        return ois.readObject(); // Deserialization gadget chain
    }

    // AA-DL-003: Stack trace leaked to user
    public String handleRequest(String userInput) {
        try {
            return ask(userInput);
        } catch (Exception e) {
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            return sw.toString();
        }
    }

    // AA-CF-003: Retry without max count
    public String retryForever(String input) {
        while (true) {
            try {
                return ask(input);
            } catch (Exception e) {
                continue;
            }
        }
    }

    // AA-DL-001: Logging sensitive data
    public String processPayment(String cardNumber, String amount) {
        logger.info("Processing payment: card=" + cardNumber + " amount=" + amount);
        return "Payment of " + amount + " processed";
    }

    // AA-CE-042: Environment variable access
    public String getSecrets() {
        return System.getenv("SECRET_KEY") + System.getenv("DATABASE_URL");
    }

    // AA-TS-039: Dump all env vars
    public String getEnvDump() {
        return System.getenv().toString();
    }

    // AA-CE-050: ProcessBuilder with user input
    public String execProcess(String cmd) throws Exception {
        ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", cmd);
        pb.redirectErrorStream(true);
        Process proc = pb.start();
        return new String(proc.getInputStream().readAllBytes());
    }

    // AA-IA-005: Spring Security misconfiguration — no CSRF
    // Typically in SecurityConfig but shown as a pattern
    public void configureNoSecurity() {
        // spring.security.enabled=false equivalent
        // No CSRF protection, no auth required
    }

    // AA-DL-046: Shared state
    public void storeGlobal(String key, Object value) {
        sharedState.put(key, value);
    }
    public Object getGlobal(String key) {
        return sharedState.get(key);
    }

    // AA-DL-052: Conversation history leak
    public void addHistory(String msg) {
        globalHistory.add(msg);
    }
    public List<String> getFullHistory() {
        return globalHistory;
    }
}
