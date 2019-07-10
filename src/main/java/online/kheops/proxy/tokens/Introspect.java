package online.kheops.proxy.tokens;

import org.glassfish.jersey.client.authentication.HttpAuthenticationFeature;

import javax.servlet.ServletContext;
import javax.ws.rs.ProcessingException;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Form;
import javax.xml.bind.annotation.XmlElement;
import java.net.URI;
import java.util.Objects;
import java.util.Optional;

import static javax.ws.rs.core.MediaType.APPLICATION_JSON_TYPE;
import static org.glassfish.jersey.client.authentication.HttpAuthenticationFeature.HTTP_AUTHENTICATION_PASSWORD;
import static org.glassfish.jersey.client.authentication.HttpAuthenticationFeature.HTTP_AUTHENTICATION_USERNAME;

public class Introspect {
    private static final Client CLIENT = ClientBuilder.newClient().register(HttpAuthenticationFeature.basicBuilder().build());

    private Introspect() {}

    private static class actingPartyResponse {
        @XmlElement(name = "sub")
        String subject;
    }

    public static class Response {
        @XmlElement(name = "active")
        boolean active;
        @XmlElement(name = "scope")
        String scope;
        @XmlElement(name = "sub")
        String subject;
        @XmlElement(name = "azp")
        String authorizedParty;
        @XmlElement(name = "cap_token")
        String capabilityTokenId;
        @XmlElement(name = "act")
        actingPartyResponse actingPartyResponse;


        public boolean isActive() {
            return active;
        }

        public String getSubject() {
            return subject;
        }

        public boolean isValidForScope(String requestedScope) {
            if (!active) {
                return false;
            }

            final String[] words = scope.split("\\s+", 40);
            for (String word : words) {
                if (word.equals(requestedScope)) {
                    return true;
                }
            }
            return false;
        }

        public Optional<String> getActingParty() {
            if (actingPartyResponse != null) {
                return Optional.of(actingPartyResponse.subject);
            }
            return Optional.empty();
        }

        public Optional<String> getAuthorizedParty() {
            return Optional.ofNullable(authorizedParty);
        }

        public Optional<String> getCapabilityTokenId() {
            return Optional.ofNullable(capabilityTokenId);
        }
    }

    public static class Introspector {
        private final ServletContext servletContext;
        private final WebTarget webTarget;

        private Introspector(ServletContext servletContext, URI endpoint) {
            this.servletContext = servletContext;
            webTarget = CLIENT.target(Objects.requireNonNull(endpoint));
        }

        public Response token(String token) throws AccessTokenException {
            final Form form = new Form()
                    .param("token", token);

            try {
                return webTarget.request(APPLICATION_JSON_TYPE)
                        .property(HTTP_AUTHENTICATION_USERNAME, servletContext.getInitParameter("online.kheops.client.dicomwebproxyclientid"))
                        .property(HTTP_AUTHENTICATION_PASSWORD, servletContext.getInitParameter("online.kheops.client.dicomwebproxysecret"))
                        .post(Entity.form(form), Response.class);
            } catch (ProcessingException | WebApplicationException e) {
                throw new AccessTokenException("Error introspecting", e);
            }
        }
    }

    public static Introspector endpoint(ServletContext servletContext, URI endpoint) {
        return new Introspector(servletContext, endpoint);
    }
}
