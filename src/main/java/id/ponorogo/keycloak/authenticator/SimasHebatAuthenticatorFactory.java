package id.ponorogo.keycloak.authenticator;

import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.ConfigurableAuthenticatorFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.models.AuthenticationExecutionModel;

import java.util.Collections;
import java.util.List;

public class SimasHebatAuthenticatorFactory implements ConfigurableAuthenticatorFactory, AuthenticatorFactory {

    public static final String ID = "simashebat-authenticator";

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public String getDisplayType() {
        return "SimasHebat Login Authenticator";
    }

    @Override
    public String getHelpText() {
        return "Login menggunakan API SimasHebat Ponorogo.";
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return new SimasHebatAuthenticator();
    }

    @Override public void init(org.keycloak.Config.Scope config) {}
    @Override public void postInit(KeycloakSessionFactory factory) {}
    @Override public void close() {}
    @Override public boolean isConfigurable() { return false; }
    @Override public boolean isUserSetupAllowed() { return false; }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return Collections.emptyList();
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[] {
            AuthenticationExecutionModel.Requirement.REQUIRED
        };
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }
}
