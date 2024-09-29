package com.program.emailProg.Server;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.mindrot.jbcrypt.BCrypt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.net.ssl.SSLServerSocketFactory;
import java.io.*;
import java.net.*;
import java.sql.*;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import com.google.gson.Gson;

public class Server {

    private static final String DB_URL = "jdbc:mysql://localhost:3306/";
    private static final String DB_USERNAME = "root";
    private static final String DB_PASSWORD = " ";
    private static final int PORT = 9999;
    private static final int MAX_THREADS = 50;
    private static HikariDataSource dataSource;
    private static ExecutorService threadPool = Executors.newFixedThreadPool(MAX_THREADS);
    private static final Logger logger = LoggerFactory.getLogger(Server.class);
    private static final Map<String, Integer> loginAttempts = new ConcurrentHashMap<>();
    private static final int MAX_LOGIN_ATTEMPTS = 5;

    public static void main(String[] args) {
        setupConnectionPool();
        logger.info("Server Starting");
        try {
            SSLServerSocketFactory ssf = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
            try (ServerSocket serverSocket = ssf.createServerSocket(PORT)) {
                logger.info("Server listening on port " + PORT);
                while (true) {
                    Socket clientSocket = serverSocket.accept();
                    logger.info("Client connected from " + clientSocket.getInetAddress());
                    threadPool.submit(new ClientHandler(clientSocket));
                }
            }
        } catch (IOException e) {
            logger.error(e.toString());
        } finally {
            threadPool.shutdown();
        }
    }

    private static void setupConnectionPool() {
        HikariConfig config = new HikariConfig();
        config.setJdbcUrl(DB_URL);
        config.setUsername(DB_USERNAME);
        config.setPassword(DB_PASSWORD);
        config.setMaximumPoolSize(10); // Limit the pool size for better resource control
        dataSource = new HikariDataSource(config);
        logger.info("Database connection pool initialized");
    }

    public static class ClientHandler implements Runnable {
        private final Socket clientSocket;
        private final Gson gson = new Gson();

        public ClientHandler(Socket socket) {
            this.clientSocket = socket;
        }

        @Override
        public void run() {
            try (BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                 PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
                 Connection connection = dataSource.getConnection()) {

                String request;
                while ((request = in.readLine()) != null) {
                    Map<String, String> requestMap = gson.fromJson(request, Map.class);
                    handleRequest(requestMap, out, connection);
                }

            } catch (IOException | SQLException e) {
                logger.error("Error in client communication", e);
            } finally {
                try {
                    clientSocket.close();
                } catch (IOException e) {
                    logger.error("Failed to close client socket", e);
                }
            }
        }

        private void handleRequest(Map<String, String> requestMap, PrintWriter out, Connection connection) throws SQLException {
            String command = requestMap.get("command").toUpperCase();

            switch (command) {
                case "LOGIN":
                    handleLogin(requestMap.get("username"), requestMap.get("password"), connection, out);
                    break;
                case "SIGN_UP":
                    handleSignUp(requestMap.get("username"), requestMap.get("password"), connection, out);
                    break;
                case "SEND":
                    handleSendEmail(requestMap.get("sender"), requestMap.get("recipient"), requestMap.get("subject"), requestMap.get("content"), connection, out);
                    break;
                case "INBOX":
                    handleInbox(requestMap.get("username"), connection, out);
                    break;
                case "READ":
                    handleReadEmail(requestMap.get("email_id"), requestMap.get("username"), out, connection);
                    break;
                case "CHECK_NOTIFICATIONS":
                    handleCheckNotifications(requestMap.get("username"), connection, out);
                    break;
                case "LOGOUT":
                    out.println(gson.toJson(Map.of("status", "LOGOUT_SUCCESS")));
                    break;
                default:
                    out.println(gson.toJson(Map.of("status", "INVALID_COMMAND")));
                    break;
            }
        }

        // Handle login with rate limiting
        private void handleLogin(String username, String password, Connection connection, PrintWriter out) throws SQLException {
            String clientIP = clientSocket.getInetAddress().toString();
            int attempts = loginAttempts.getOrDefault(clientIP, 0);

            if (attempts >= MAX_LOGIN_ATTEMPTS) {
                out.println(gson.toJson(Map.of("status", "LOGIN_FAILED", "message", "Too many attempts")));
                return;
            }

            String query = "SELECT password_hash FROM users WHERE username = ?";
            try (PreparedStatement ps = connection.prepareStatement(query)) {
                ps.setString(1, username);
                ResultSet rs = ps.executeQuery();

                if (rs.next()) {
                    String storedHash = rs.getString("password_hash");
                    if (BCrypt.checkpw(password, storedHash)) {
                        out.println(gson.toJson(Map.of("status", "LOGIN_SUCCESS")));
                        loginAttempts.remove(clientIP); // reset attempts after success
                    } else {
                        loginAttempts.put(clientIP, attempts + 1);
                        out.println(gson.toJson(Map.of("status", "LOGIN_FAILED", "message", "Incorrect password")));
                    }
                } else {
                    out.println(gson.toJson(Map.of("status", "LOGIN_FAILED", "message", "User not found")));
                }
            }
        }

        // Handle user sign up
        private void handleSignUp(String username, String password, Connection connection, PrintWriter out) throws SQLException {
            String hashedPassword = BCrypt.hashpw(password, BCrypt.gensalt());
            String query = "INSERT INTO users (username, password_hash) VALUES (?, ?)";

            try (PreparedStatement ps = connection.prepareStatement(query)) {
                ps.setString(1, username);
                ps.setString(2, hashedPassword);
                int result = ps.executeUpdate();
                if (result > 0) {
                    out.println(gson.toJson(Map.of("status", "SIGN_UP_SUCCESS")));
                } else {
                    out.println(gson.toJson(Map.of("status", "SIGN_UP_FAILED")));
                }
            }
        }

        // Handle email sending
        private void handleSendEmail(String sender, String recipient, String subject, String content, Connection connection, PrintWriter out) throws SQLException {
            String query = "INSERT INTO emails (sender_id, recipient_id, subject, content) VALUES ((SELECT user_id FROM users WHERE username = ?), (SELECT user_id FROM users WHERE username = ?), ?, ?)";
            try (PreparedStatement ps = connection.prepareStatement(query)) {
                ps.setString(1, sender);
                ps.setString(2, recipient);
                ps.setString(3, subject);
                ps.setString(4, content);
                int result = ps.executeUpdate();
                out.println(gson.toJson(Map.of("status", result > 0 ? "SENT" : "SEND_FAILED")));
            }
        }

        // Handle inbox request
        private void handleInbox(String username, Connection connection, PrintWriter out) throws SQLException {
            String query = "SELECT email_id, sender_id, subject, sent_at, is_read FROM emails WHERE recipient_id = (SELECT user_id FROM users WHERE username = ?) ORDER BY sent_at DESC";
            try (PreparedStatement ps = connection.prepareStatement(query)) {
                ps.setString(1, username);
                ResultSet rs = ps.executeQuery();
                StringBuilder result = new StringBuilder();
                while (rs.next()) {
                    result.append(rs.getInt("email_id")).append("|")
                            .append(rs.getInt("sender_id")).append("|")
                            .append(rs.getString("subject")).append("|")
                            .append(rs.getTimestamp("sent_at")).append("|")
                            .append(rs.getBoolean("is_read")).append("\n");
                }
                out.println(result.toString());
            }
        }

        // Handle reading emails
        private void handleReadEmail(String emailId, String username, PrintWriter out, Connection connection) throws SQLException {
            String query = "UPDATE emails SET is_read = true, read_at = CURRENT_TIMESTAMP WHERE email_id = ? AND recipient_id = (SELECT user_id FROM users WHERE username = ?) AND is_read = false";
            try (PreparedStatement ps = connection.prepareStatement(query)) {
                ps.setString(1, emailId);
                ps.setString(2, username);
                int result = ps.executeUpdate();
                out.println(gson.toJson(Map.of("status", result > 0 ? "READ_SUCCESS" : "READ_FAILED")));
            }
        }

        // Handle notification checking
        private void handleCheckNotifications(String username, Connection connection, PrintWriter out) throws SQLException {
            String query = "SELECT e.email_id, e.subject, u.username AS recipient, e.read_at FROM emails e JOIN users u ON e.recipient_id = u.user_id WHERE e.sender_id = (SELECT user_id FROM users WHERE username = ?) AND e.is_read = true AND e.is_sender_notified = false";
            try (PreparedStatement ps = connection.prepareStatement(query)) {
                ps.setString(1, username);
                ResultSet rs = ps.executeQuery();
                StringBuilder sb = new StringBuilder();
                while (rs.next()) {
                    sb.append("Email ID: ").append(rs.getInt("email_id"))
                            .append(", Subject: ").append(rs.getString("subject"))
                            .append(", Read by: ").append(rs.getString("recipient"))
                            .append(", Read at: ").append(rs.getTimestamp("read_at"))
                            .append("\n");
                    markAsNotified(rs.getInt("email_id"), connection);
                }
                out.println(gson.toJson(Map.of("notifications", sb.length() > 0 ? sb.toString() : "NO_NEW_NOTIFICATIONS")));
            }
        }

        private void markAsNotified(int emailId, Connection connection) throws SQLException {
            String query = "UPDATE emails SET is_sender_notified = true WHERE email_id = ?";
            try (PreparedStatement ps = connection.prepareStatement(query)) {
                ps.setInt(1, emailId);
                ps.executeUpdate();
            }
        }
    }
}
