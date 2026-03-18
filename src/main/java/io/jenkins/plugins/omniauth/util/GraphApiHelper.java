package io.jenkins.plugins.omniauth.util;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jenkins.plugins.omniauth.EntraGroupDetails;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Calls the Microsoft Graph API to retrieve group memberships for the authenticated user.
 * Uses Java 11's built-in HttpClient to avoid external HTTP library dependencies.
 *
 * Requires the access token to have 'GroupMember.Read.All' delegated permission
 * with admin consent granted in the Azure AD app registration.
 */
public class GraphApiHelper {

    private static final Logger LOGGER = Logger.getLogger(GraphApiHelper.class.getName());
    private static final String GRAPH_BASE = "https://graph.microsoft.com/v1.0";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final HttpClient httpClient;

    public GraphApiHelper() {
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }

    /**
     * Retrieves all Azure AD group memberships for the currently authenticated user.
     * Handles pagination automatically via @odata.nextLink.
     *
     * @param accessToken Bearer token with GroupMember.Read.All scope
     * @return List of EntraGroupDetails representing the user's group memberships
     */
    public List<EntraGroupDetails> getGroupMemberships(String accessToken) throws IOException, InterruptedException {
        List<EntraGroupDetails> groups = new ArrayList<>();
        String nextUrl = GRAPH_BASE + "/me/memberOf?$select=id,displayName&$top=100";

        while (nextUrl != null) {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(nextUrl))
                    .header("Authorization", "Bearer " + accessToken)
                    .header("Accept", "application/json")
                    .timeout(Duration.ofSeconds(15))
                    .GET()
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                LOGGER.log(Level.WARNING,
                        "Graph API group lookup failed: HTTP {0}", response.statusCode());
                break;
            }

            JsonNode root = MAPPER.readTree(response.body());

            JsonNode values = root.get("value");
            if (values != null && values.isArray()) {
                for (JsonNode node : values) {
                    String id = node.path("id").asText(null);
                    String displayName = node.path("displayName").asText(null);
                    if (id != null && displayName != null) {
                        groups.add(new EntraGroupDetails(id, displayName));
                    }
                }
            }

            // Follow pagination link if present
            JsonNode nextLink = root.get("@odata.nextLink");
            nextUrl = (nextLink != null && !nextLink.isNull()) ? nextLink.asText() : null;
        }

        LOGGER.log(Level.FINE, "Graph API: found {0} group memberships", groups.size());
        return groups;
    }
}
