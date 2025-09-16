package id.ponorogo.keycloak.authenticator;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.KeycloakSession;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
// import java.util.Map;
import jakarta.ws.rs.core.MultivaluedMap;
import org.jboss.logging.Logger;


public class SimasHebatAuthenticator implements Authenticator {
    private static final Logger logger = Logger.getLogger(SimasHebatAuthenticator.class);

    /**
     * Handle silent login. Return true jika silent login sukses, false jika tidak.
     */
    private boolean handleSilentLogin(AuthenticationFlowContext context) {
        String prompt = context.getAuthenticationSession().getClientNote("prompt");
        boolean isSilent = "none".equals(prompt);

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String username = formData.get("username") != null && !formData.get("username").isEmpty() ? formData.get("username").get(0) : null;
        String password = formData.get("password") != null && !formData.get("password").isEmpty() ? formData.get("password").get(0) : null;

        if (isSilent && (username == null || password == null)) {
            UserModel user = context.getUser();
            if (user == null) {
                user = context.getAuthenticationSession().getAuthenticatedUser();
            }
            logger.infof("Silent login detected. User from context: %s", user != null ? user.getUsername() : "null");
            if (user != null) {
                logger.infof("Silent login berhasil. User sudah login sebelumnya: %s", user.getUsername());
                context.setUser(user);
                context.success();
                return true;
            }
        }
        return false;
    }

    private void showLoginFormIfNeeded(AuthenticationFlowContext context, String username, String password) {
        if (username == null || password == null) {
            logger.info("Menampilkan form login bawaan Keycloak");
            context.challenge(context.form().createLoginUsernamePassword());
        }
    }

    private void processSimasHebatLogin(AuthenticationFlowContext context, String username, String password) {
        try {
            String url = "https://simashebat.ponorogo.go.id/api/v1/external/auth/";
            String jsonBody = String.format("{\"app_id\":\"976c7127-4e15-43f5-8852-657b5c405972\",\"username\":\"%s\",\"password\":\"%s\"}", username, password);

            URL obj = new URL(url);
            HttpURLConnection con = (HttpURLConnection) obj.openConnection();
            con.setRequestMethod("POST");
            con.setRequestProperty("Accept", "application/json");
            con.setRequestProperty("Content-Type", "application/json");
            con.setRequestProperty("Authorization", "Bearer 2440efe5-d000-4089-bd5d-e57e547ca709");
            con.setDoOutput(true);
            try (DataOutputStream wr = new DataOutputStream(con.getOutputStream())) {
                wr.write(jsonBody.getBytes(StandardCharsets.UTF_8));
            }

            int responseCode = con.getResponseCode();
            if (responseCode != 200 && responseCode != 201) {
                context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
                    context.form()
                        .setError("invalid_credentials", "Invalid Credentials.")
                        .createLoginUsernamePassword());
                return;
            }

            BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
            String inputLine;
            StringBuilder response = new StringBuilder();
            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }
            in.close();

            String json = response.toString();
            System.out.println("[SimasHebatAuthenticator] Response from SimasHebat API: " + json);

            // Parse response: { "message": ..., "access": true, "data": { "nip": ..., "nama": ..., "email": ... } }
            boolean access = json.contains("\"access\":true");
            if (access && json.contains("\"data\":")) {
                String data = json.substring(json.indexOf("\"data\":") + 7);
                if (data.startsWith("{")) {
                    int endIdx = data.indexOf("}") + 1;
                    data = data.substring(0, endIdx);
                }
                String nip = extractJsonValue(data, "nip");
                String nama = extractJsonValue(data, "nama");
                String email = extractJsonValue(data, "email");

                System.out.println("[SimasHebatAuthenticator] nip: " + nip + ", nama: " + nama + ", email: " + email);

                UserModel user = context.getSession().users().getUserByUsername(context.getRealm(), nip);
                if (user == null) {
                    user = context.getSession().users().addUser(context.getRealm(), nip);
                    System.out.println("[SimasHebatAuthenticator] User baru dibuat di Keycloak: " + nip);
                } else {
                    System.out.println("[SimasHebatAuthenticator] User sudah ada di Keycloak: " + nip);
                }
                user.setEnabled(true);
                if (nama != null && nama.contains(" ")) {
                    String[] parts = nama.trim().split(" ", 2);
                    user.setFirstName(parts[0]);
                    user.setLastName(parts.length > 1 ? parts[1] : "");
                } else {
                    user.setFirstName(nama);
                }
                if (email != null) user.setEmail(email);
                if (nip != null) user.setSingleAttribute("nip", nip);

                System.out.println("[SimasHebatAuthenticator] User sudah di-set di context dan akan success.");
                context.setUser(user);
                context.success();
            } else {
                context.failureChallenge(AuthenticationFlowError.INVALID_USER,
                    context.form()
                        .setError("invalidUserMessage")
                        .createLoginUsernamePassword());
            }
        } catch (Exception e) {
            context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
                context.form()
                    .setError("errorMessage", "An error occurred while processing your request: " + e.getMessage())
                    .createLoginUsernamePassword());
        }
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        logger.info("=== SimasHebatAuthenticator.authenticate() CALLED ===");
        context.getHttpRequest().getHttpHeaders().getRequestHeaders().forEach((k, v) -> {
            logger.infof("Header: %s = %s", k, v);
        });

        UserModel user = context.getUser();
        if (user == null) {
            user = context.getAuthenticationSession().getAuthenticatedUser();
        }
        if (user != null) {
            logger.infof("User sudah ada di context, langsung success: %s", user.getUsername());
            context.setUser(user);
            context.success();
            return;
        }

        UserModel user1 = context.getUser();
        UserModel user2 = context.getAuthenticationSession().getAuthenticatedUser();
        UserModel user3 = context.getSession().getContext().getAuthenticationSession().getAuthenticatedUser();
        logger.infof("User from context.getUser(): %s", user1 != null ? user1.getUsername() : "null");
        logger.infof("User from context.getAuthenticationSession().getAuthenticatedUser(): %s", user2 != null ? user2.getUsername() : "null");
        logger.infof("User from context.getSession().getContext().getAuthenticationSession().getAuthenticatedUser(): %s", user3 != null ? user3.getUsername() : "null");

        // Sempurnakan silent login: jika sukses, langsung return
        if (handleSilentLogin(context)) {
            return;
        }

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        logger.infof("Form data keys: %s", formData.keySet());

        String username = formData.get("username") != null && !formData.get("username").isEmpty() ? formData.get("username").get(0) : null;
        String password = formData.get("password") != null && !formData.get("password").isEmpty() ? formData.get("password").get(0) : null;

        logger.infof("Username: %s, Password present: %s", username, password != null);

        if (username == null || password == null) {
            logger.info("Menampilkan form login bawaan Keycloak");
            context.challenge(context.form().createLoginUsernamePassword());
            return;
        }

        logger.info("[SimasHebatAuthenticator] Response from SimasHebat API");
        processSimasHebatLogin(context, username, password);
    }

    // Helper method for simple JSON value extraction
    private static String extractJsonValue(String json, String key) {
        String pattern = "\"" + key + "\":\"";
        int idx = json.indexOf(pattern);
        if (idx == -1) return null;
        int start = idx + pattern.length();
        int end = json.indexOf("\"", start);
        if (end == -1) return null;
        return json.substring(start, end);
    }


    @Override
    public void action(AuthenticationFlowContext context) {
        // Tangani submit form login, lakukan proses yang sama seperti authenticate
        authenticate(context);
    }

    @Override public boolean requiresUser() { return false; }
    @Override public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) { return true; }
    @Override public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {}
    @Override public void close() {}
}
