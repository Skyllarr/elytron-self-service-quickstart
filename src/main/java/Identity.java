import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.SecurityContext;
import java.security.Principal;
import java.util.*;

import org.json.JSONArray;
import org.json.JSONObject;
import org.wildfly.security.WildFlyElytronProvider;
import org.wildfly.security.auth.server.ModifiableRealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.authz.MapAttributes;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.spec.ClearPasswordSpec;

import static org.wildfly.security.authz.RoleDecoder.KEY_ROLES;
import static org.wildfly.security.password.interfaces.ClearPassword.ALGORITHM_CLEAR;

@Path("/")
public class Identity {

    public static final String PASSWORD = "password";

    @Context
    private SecurityContext securityContext;

    @GET
    @Path("/admin")
    @Produces("text/plain")
    @RolesAllowed("Admin")
    public String attributesAdmin() throws RealmUnavailableException {
        return getIdentityInformation();
    }

    @GET
    @Path("/user")
    @Produces("text/plain")
    @RolesAllowed("User")
    public String attributesUser() throws RealmUnavailableException {
        return getIdentityInformation();
    }

    @GET
    @PermitAll
    @Path("/guest")
    @Produces("text/plain")
    public String attributesGuest() throws RealmUnavailableException {
        return getIdentityInformation();
    }

    @GET
    @Path("/admin/update")
    @Produces("text/plain")
    @RolesAllowed("Admin")
    public String credentialsGuest() throws RealmUnavailableException {
        return getIdentityInformation();
    }

    @POST
    @Path("/user/update")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces("text/plain")
    @RolesAllowed("User")
    public String updateUserAttributes(String json) throws Exception {
        return updateIdentity(json);
    }

    @POST
    @Path("/admin/update")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces("text/plain")
    @RolesAllowed("Admin")
    public String updateAdminAttributes(String json) throws Exception {
        return updateIdentity(json);
    }

    private String updateIdentity(String json) throws Exception {
        return updateAttributes(new JSONObject(json.trim()).toString());
    }

    private String getIdentityInformation() throws RealmUnavailableException {
        Principal userPrincipal = securityContext.getUserPrincipal();
        String principalName = userPrincipal == null ? "anonymous" : userPrincipal.getName();
        SecurityIdentity identity = SecurityDomain.getCurrent().getCurrentSecurityIdentity();
        Attributes attributes = identity.getAttributes();
        StringBuilder stringAttributes = new StringBuilder();
        for (String attribute : attributes.keySet()) {
            stringAttributes.append(attribute).append(": ").append(attributes.get(attribute)).append("\n");
        }
        return "Hello " + principalName + "! \n" +
                "You have " + identity.getAttributes().size() + " attributes:\n\n" + stringAttributes;
    }

    private String updateAttributes(String json) throws Exception {
        JSONObject jsonObj = new JSONObject(json.trim());
        if (jsonObj.keySet().contains(KEY_ROLES)) {
            return "Cannot modify own roles.";
        } else {
            ModifiableRealmIdentity modifiableIdentity = SecurityDomain.getCurrent().getIdentityForUpdate(securityContext.getUserPrincipal());
            MapAttributes attributes = new MapAttributes(modifiableIdentity.getAttributes());
            Iterator<String> keys = jsonObj.keys();
            while (keys.hasNext()) {
                String key = keys.next();
                if (key.equalsIgnoreCase(PASSWORD)) {
                    updatePassword(modifiableIdentity, jsonObj.getString(key));
                    continue;
                }
                List<String> values = getValuesFromJson(new JSONArray(jsonObj.get(key).toString()));
                if (attributes.containsKey(key)) {
                    attributes.copyAndReplace(key, values);
                } else {
                    attributes.addAll(key, values);
                }
            }
            modifiableIdentity.setAttributes(attributes);
            modifiableIdentity.dispose();
            return "Successfully updated";
        }
    }

    private List<String> getValuesFromJson(JSONArray jsonArray) {
        List<String> list = new ArrayList<String>();
        for (int i = 0; i < jsonArray.length(); i++) {
            list.add(jsonArray.getString(i));
        }
        return list;
    }

    private void updatePassword(ModifiableRealmIdentity modifiableIdentity, String newPassword) throws Exception {
        PasswordFactory passwordFactory = PasswordFactory.getInstance(ALGORITHM_CLEAR, new WildFlyElytronProvider());
        PasswordCredential updatedPassword = new PasswordCredential(passwordFactory.generatePassword(new ClearPasswordSpec(newPassword.toCharArray())));
        HashSet<Credential> newCredentials = new HashSet<Credential>();
        newCredentials.add(updatedPassword);
        modifiableIdentity.setCredentials(newCredentials);
        modifiableIdentity.dispose();
    }
}