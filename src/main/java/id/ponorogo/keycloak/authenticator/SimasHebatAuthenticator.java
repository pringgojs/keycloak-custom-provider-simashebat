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

    // Constants
    private static final String SIMAS_API_URL = "https://simashebat.ponorogo.go.id/api/v1/external/auth/";
    private static final String SIMAS_API_CHECK_URL = "https://simashebat.ponorogo.go.id";
    private static final String INFO_DOWN = "Sistem SSO sedang mengalami gangguan koneksi ke Simas Hebat. Login kemungkinan gagal. Silakan coba beberapa saat lagi.";
    private static final String SIMAS_API_AUTH = "Bearer 2440efe5-d000-4089-bd5d-e57e547ca709";
    private static final int TIMEOUT = 2000;

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        logger.info("=== SimasHebatAuthenticator.authenticate() CALLED ===");
        context.getHttpRequest().getHttpHeaders().getRequestHeaders().forEach((k, v) -> {
            logger.infof("Header: %s = %s", k, v);
        });

        UserModel user = getUserFromContext(context);
        if (user != null) {
            logger.infof("User sudah ada di context, langsung success: %s", user.getUsername());
            context.setUser(user);
            context.success();
            return;
        }

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        logger.infof("Form data keys: %s", formData.keySet());
        String username = getFormValue(formData, "username");
        String password = getFormValue(formData, "password");
        logger.infof("Username: %s, Password present: %s", username, password != null);

        if (username == null || password == null) {
            if (!isSimasHebatApiAvailable()) {
                logger.info("SimasHebat API tidak bisa diakses, tampilkan error di form login");
                context.challenge(
                    context.form()
                        .setError(INFO_DOWN)
                        .createLoginUsernamePassword()
                );
                return;
            }
            logger.info("Menampilkan form login bawaan Keycloak");
            context.challenge(context.form().createLoginUsernamePassword());
            return;
        }

        logger.info("[SimasHebatAuthenticator] Response from SimasHebat API");
        processSimasHebatLogin(context, username, password);
    }

    // Helper: get user from context/session
    private UserModel getUserFromContext(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        if (user == null) user = context.getAuthenticationSession().getAuthenticatedUser();
        if (user == null && context.getSession() != null && context.getSession().getContext() != null && context.getSession().getContext().getAuthenticationSession() != null) {
            user = context.getSession().getContext().getAuthenticationSession().getAuthenticatedUser();
        }
        return user;
    }

    // Helper: get value from form
    private String getFormValue(MultivaluedMap<String, String> formData, String key) {
        return formData.get(key) != null && !formData.get(key).isEmpty() ? formData.get(key).get(0) : null;
    }

    // Helper: check SimasHebat API availability (homepage)
    private boolean isSimasHebatApiAvailable() {
        try {
            logger.info("url simas: " + SIMAS_API_CHECK_URL);
            URL url = new URL(SIMAS_API_CHECK_URL);
            HttpURLConnection con = (HttpURLConnection) url.openConnection();
            con.setRequestMethod("GET");
            con.setConnectTimeout(TIMEOUT);
            con.setReadTimeout(TIMEOUT);
            int responseCode = con.getResponseCode();
            logger.info("Status cek koneksi ke SimasHebat: " + responseCode);

            return responseCode >= 200 && responseCode < 500;
        } catch (Exception e) {
            logger.info("Error saat cek koneksi ke SimasHebat: " + e.getMessage());

            return false;
        }
    }

    // Helper: create or update user in Keycloak
    private UserModel createOrUpdateUser(AuthenticationFlowContext context, String nip, String nama, String email) {
        UserModel user = context.getSession().users().getUserByUsername(context.getRealm(), nip);
        if (user == null) {
            user = context.getSession().users().addUser(context.getRealm(), nip);
            logger.infof("User baru dibuat di Keycloak: %s", nip);
        } else {
            logger.infof("User sudah ada di Keycloak: %s", nip);
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
        return user;
    }

    // Helper: extract value from JSON (simple)
    private static String extractJsonValue(String json, String key) {
        String pattern = "\"" + key + "\":\"";
        int idx = json.indexOf(pattern);
        if (idx == -1) return null;
        int start = idx + pattern.length();
        int end = json.indexOf("\"", start);
        if (end == -1) return null;
        return json.substring(start, end);
    }

    // Main login process
    private void processSimasHebatLogin(AuthenticationFlowContext context, String username, String password) {
        try {
            String jsonBody = String.format("{\"app_id\":\"976c7127-4e15-43f5-8852-657b5c405972\",\"username\":\"%s\",\"password\":\"%s\"}", username, password);
            URL obj = new URL(SIMAS_API_URL);
            HttpURLConnection con = (HttpURLConnection) obj.openConnection();
            con.setRequestMethod("POST");
            con.setRequestProperty("Accept", "application/json");
            con.setRequestProperty("Content-Type", "application/json");
            con.setRequestProperty("Authorization", SIMAS_API_AUTH);
            con.setConnectTimeout(TIMEOUT);
            con.setReadTimeout(TIMEOUT);
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

            StringBuilder response = new StringBuilder();
            try (BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()))) {
                String inputLine;
                while ((inputLine = in.readLine()) != null) {
                    response.append(inputLine);
                }
            }

            String json = response.toString();
            logger.infof("[SimasHebatAuthenticator] Response from SimasHebat API: %s", json);

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

                logger.infof("[SimasHebatAuthenticator] nip: %s, nama: %s, email: %s", nip, nama, email);
                UserModel user = createOrUpdateUser(context, nip, nama, email);
                logger.info("[SimasHebatAuthenticator] User sudah di-set di context dan akan success.");
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
    public void action(AuthenticationFlowContext context) {
        authenticate(context);
    }

    @Override public boolean requiresUser() { return false; }
    @Override public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) { return true; }
    @Override public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {}
    @Override public void close() {}
}
