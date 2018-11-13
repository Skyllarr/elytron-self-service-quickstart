import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.SecurityContext;
import java.security.Principal;
import java.util.*;

import org.json.JSONArray;
import org.json.JSONObject;
import org.wildfly.security.auth.server.ModifiableRealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.authz.MapAttributes;


@Path("/")
public class Identity {

    @Context
    private SecurityContext securityContext;

    @GET
    @Path("/admin")
    @Produces("text/plain")
//    @RolesAllowed({"Admin"}) TODO why this doesn't work?
    public String attributesAdmin() throws RealmUnavailableException {
        return getIdentityInformation();
    }

    @GET
    @Path("/user")
    @Produces("text/plain")
    public String attributesUser() throws RealmUnavailableException {
        return getIdentityInformation();
    }

    @GET
    @Path("/guest")
    @Produces("text/plain")
    public String attributesGuest() throws RealmUnavailableException {
        return getIdentityInformation();
    }

    @GET
    @Path("/admin/update")
    @Produces("text/plain")
    public String credentialsGuest() throws RealmUnavailableException {
        return getIdentityInformation();
    }

    @POST
    @Path("/user/update")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces("text/plain")
    public String updateUserAttributes(String json) throws RealmUnavailableException {
        return updateIdentity(json);
    }

    @POST
    @Path("/admin/update")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces("text/plain")
    public String updateAdminAttributes(String json) throws RealmUnavailableException {
        return updateIdentity(json);
    }

    private String updateIdentity(String json) throws RealmUnavailableException {
        updateAttributes(new JSONObject(json.trim()).toString());
        return "Successfully updated";
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

    private void updateAttributes(String json) throws RealmUnavailableException {
        ModifiableRealmIdentity modifiableIdentity = SecurityDomain.getCurrent().getIdentityForUpdate(securityContext.getUserPrincipal());
        MapAttributes attributes = new MapAttributes(modifiableIdentity.getAttributes());
        JSONObject jsonObj = new JSONObject(json.trim());
        Iterator<String> keys = jsonObj.keys();
        while (keys.hasNext()) {
            String key = keys.next();
            List<String> values = getValuesFromJson(new JSONArray(jsonObj.get(key).toString()));
            if (attributes.containsKey(key)) {
                attributes.copyAndReplace(key, values);
            } else {
                attributes.addAll(key, values);
            }
        }
        modifiableIdentity.setAttributes(attributes);
        modifiableIdentity.dispose();
    }

    private List<String> getValuesFromJson(JSONArray jsonArray) {
        List<String> list = new ArrayList<String>();
        for (int i=0; i<jsonArray.length(); i++) {
            list.add( jsonArray.getString(i));
        }
        return list;
    }

    private void updateCredentials(String json) throws RealmUnavailableException {
        // TODO public credentials update
    }
}