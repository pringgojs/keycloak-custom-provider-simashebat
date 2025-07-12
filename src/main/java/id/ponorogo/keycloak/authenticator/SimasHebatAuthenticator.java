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

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        logger.info("=== SimasHebatAuthenticator.authenticate() CALLED ===");

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        logger.infof("Form data keys: %s", formData.keySet());

        String username = formData.get("username") != null && !formData.get("username").isEmpty() ? formData.get("username").get(0) : null;
        String password = formData.get("password") != null && !formData.get("password").isEmpty() ? formData.get("password").get(0) : null;

        logger.infof("Username: %s, Password present: %s", username, password != null);

        // Jika username/password belum diisi, tampilkan form bawaan Keycloak
        if (username == null || password == null) {
            logger.info("Menampilkan form login bawaan Keycloak");
            context.challenge(context.form().createLoginUsernamePassword());
            return;
        }

        logger.info("[SimasHebatAuthenticator] Response from SimasHebat API");

        try {
            // Hash password to MD5 before sending
            String md5Password = md5Hex(password);
            logger.info("Password hashed to MD5");

            // Prepare request
            String url = "https://api-simashebat.ponorogo.go.id/";
            String urlParameters = "username=" + username + "&password=" + md5Password;
            byte[] postData = urlParameters.getBytes(StandardCharsets.UTF_8);

            URL obj = new URL(url);
            HttpURLConnection con = (HttpURLConnection) obj.openConnection();
            con.setRequestMethod("POST");
            con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            con.setDoOutput(true);
            try (DataOutputStream wr = new DataOutputStream(con.getOutputStream())) {
                wr.write(postData);
            }

            int responseCode = con.getResponseCode();
            if (responseCode != 200) {
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
            // Simple JSON parsing (no external lib)
            if (json.contains("\"success\":true")) {
                // Extract data fields manually (for production, use a JSON lib)
                String data = json.substring(json.indexOf("\"data\":") + 7);
                // Only take the object part
                if (data.startsWith("{")) {
                    int endIdx = data.indexOf("}") + 1;
                    data = data.substring(0, endIdx);
                }
                // Get some fields (nip_baru, nama, email, pegawai_id)
                String nipBaru = extractJsonValue(data, "nip_baru");
                String nama = extractJsonValue(data, "nama");
                String email = extractJsonValue(data, "email");
                String pegawaiId = extractJsonValue(data, "pegawai_id");

                System.out.println("[SimasHebatAuthenticator] nipBaru: " + nipBaru + ", nama: " + nama + ", email: " + email + ", pegawaiId: " + pegawaiId);

                // Find or create user in Keycloak
                UserModel user = context.getSession().users().getUserByUsername(context.getRealm(), nipBaru);
                if (user == null) {
                    user = context.getSession().users().addUser(context.getRealm(), nipBaru);
                    System.out.println("[SimasHebatAuthenticator] User baru dibuat di Keycloak: " + nipBaru);
                } else {
                    System.out.println("[SimasHebatAuthenticator] User sudah ada di Keycloak: " + nipBaru);
                }
                user.setEnabled(true);
                if (nama != null && nama.contains(" ")) {
                    String[] parts = nama.split(" ", 2);
                    user.setFirstName(parts[0]);
                    user.setLastName(parts[1]);
                } else {
                    user.setFirstName(nama);
                }
                if (email != null) user.setEmail(email);
                if (pegawaiId != null) user.setSingleAttribute("pegawai_id", pegawaiId);
                if (nipBaru != null) user.setSingleAttribute("nip_baru", nipBaru);

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

    // Helper method to hash string to MD5 hex
    private static String md5Hex(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b & 0xff));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
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
