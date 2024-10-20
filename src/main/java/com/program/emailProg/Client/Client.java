package com.program.emailProg.Client;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.Map;

public class Client {

    private static final String SERVER_ADDRESS = "localhost";
    private static final int SERVER_PORT = 8080;
    private static Gson gson = new Gson();
    private static Socket socket;
    private static BufferedReader in;
    private static BufferedReader consoleInput;
    private static PrintWriter out;

    public static void main(String[] args) {
        try {
            setupConnection();
            boolean isLoggedIn = false;

            while (!isLoggedIn) {
                System.out.print("\n1. Log in\n2. Sign up\nEnter: ");
                String userIn = consoleInput.readLine();
                if (userIn.equalsIgnoreCase("log in")) {
                    isLoggedIn = login();
                } else if (userIn.equalsIgnoreCase("sign up")) {
                    signUp();
                }
            }

            while (true) {
                handleUserCommand();
            }
        } catch (IOException e) {
            System.out.println(e.getMessage());
        } finally {
            disconnectFromServer();
        }
    }

    private static void disconnectFromServer() {
        try {
            if (socket != null && !socket.isClosed()) {
                socket.close();
            }
            System.out.println("Disconnected from server");
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }
    }

    private static void setupConnection() {
        try  {
            socket = new Socket(SERVER_ADDRESS, SERVER_PORT);
            in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            consoleInput = new BufferedReader(new InputStreamReader(System.in));
            out = new PrintWriter(socket.getOutputStream(), true);
            System.out.printf("Connected at %s: %d", SERVER_ADDRESS, SERVER_PORT);
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }
    }

    private static boolean login() throws IOException {
        System.out.print("Enter username: ");
        String username = consoleInput.readLine();
        System.out.print("Enter password: ");
        String password = consoleInput.readLine();

        Map<String, String> loginReq = Map.of(
                "command", "Login",
                "username", username,
                "password", password
        );
        sendRequest(loginReq);

        String response = readResponse();
        Map<String, String> responseMap = gson.fromJson(response, Map.class);
        try {
            if ("LOGIN_SUCCESS".equalsIgnoreCase(responseMap.get("status"))) {
                System.out.println("Login Successful");
                return true;
            } else {
                System.out.println("Login Failed" + responseMap.get("message"));
                return false;
            }
        } catch (JsonSyntaxException e) {
            System.out.println("Response: " + response);
            return false;
        }
    }

    private static void signUp() throws IOException {
        System.out.print("Enter username: ");
        String username = consoleInput.readLine();
        System.out.print("Enter password: ");
        String password = consoleInput.readLine();

        Map<String, String> signUpRequest = Map.of(
                "command", "SIGN_UP",
                "username", username,
                "password", password
        );
        sendRequest(signUpRequest);

        String response = readResponse();
        try {
            // Attempt to parse as a JSON object
            Map<String, String> responseMap = gson.fromJson(response, Map.class);
            if ("SIGN_UP_SUCCESS".equals(responseMap.get("status"))) {
                System.out.println("Sign-up successful! You can now log in.");
            } else {
                System.out.println("Sign-up failed. Please try again.");
            }
        } catch (JsonSyntaxException e) {
            // Handle if the response is just a plain string
            System.out.println("Response: " + response);
        }
    }


    private static void handleUserCommand() throws IOException {
        showMenu();
        String command = consoleInput.readLine();
        switch (command) {
            case "1":
                sendEmail();
                break;
            case "2":
                viewInbox();
                break;
            case "3":
                readEmail();
                break;
            case "4":
                checkNotifications();
                break;
            case "5":
                logout();
                break;
            default:
                System.out.println("Invalid command");
        }

    }

    private static void sendEmail() throws IOException {
        System.out.print("Sender username: "); String sender = consoleInput.readLine();
        System.out.print("Recipient username: "); String recipient = consoleInput.readLine();
        System.out.print("Subject: "); String subject = consoleInput.readLine();
        System.out.print("Content: "); String content = consoleInput.readLine();

        Map<String, String> emailRequest = Map.of(
                "command", "SEND",
                "sender", sender,
                "recipient", recipient,
                "subject", subject,
                "content", content
        );
        sendRequest(emailRequest);

        String response = readResponse();
        Map<String, String> responseMap = gson.fromJson(response, Map.class);

        System.out.println(responseMap.get("status").equals("SENT") ? "Email sent" : "Failed to send");
    }

    private static void viewInbox() throws IOException {
        System.out.print("Enter your username: ");
        String username = consoleInput.readLine();

        Map<String, String> inboxRequest = Map.of(
                "command", "INBOX",
                "username", username
        );
        sendRequest(inboxRequest);

        String response = readResponse();
        System.out.println("Inbox:\n" + response);
    }

    private static void readEmail() throws IOException{
        System.out.print("Enter your username: "); String username = consoleInput.readLine();
        System.out.print("Enter email ID to read: "); String emailId = consoleInput.readLine();

        Map<String, String> readRequest = Map.of(
                "command", "READ",
                "email_id", emailId,
                "username", username
        );
        sendRequest(readRequest);

        String response = readResponse();
        System.out.println(response);
    }

    private static void checkNotifications() throws IOException{
        System.out.print("Enter your username: ");
        String username = consoleInput.readLine();

        Map<String, String> notificationRequest = Map.of(
                "command", "CHECK_NOTIFICATIONS",
                "username", username
        );
        sendRequest(notificationRequest);

        String response = readResponse();
        System.out.println("Notifications:\n" + response);
    }

    private static void logout() {
        Map<String, String> logoutRequest = Map.of("command", "LOGOUT");
        sendRequest(logoutRequest);
        System.out.println("Logged out.");
        disconnectFromServer();
        System.exit(0);
    }

    private static String readResponse() {
        try {
            String response = in.readLine();
            System.out.println("Raw response: " + response);  // Add this line to inspect
            return response;
        } catch (IOException e) {
            throw new RuntimeException("Failed to read response from server", e);
        }
    }


    private static void sendRequest(Map<String, String> loginReq) {
        String requestJson = gson.toJson(loginReq);
        out.println(requestJson);
    }

    private static void showMenu() {
        System.out.println("= Menu =\n1. Send Email\n2. View Inbox\n3. Read Email\n4. Check Notifications\n5. Logout\nEnter Command: ");
    }
}
