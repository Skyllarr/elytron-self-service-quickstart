import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.SecurityContext;
import java.security.Principal;

import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.authz.Attributes;


@Path("/")
public class Identity {

    @Context
    private SecurityContext securityContext;

    @GET
    @Path("/admin")
    @Produces("text/plain")
//    @RolesAllowed({"Admin"}) why this doesn't work?
    public String helloAdmin() throws RealmUnavailableException {
        return getPrintableInfo();
    }

    @GET
    @Path("/user")
    @Produces("text/plain")
//    @RolesAllowed({"User"}) why this doesn't work?
    public String helloUser() throws RealmUnavailableException {
        return getPrintableInfo();
    }

    @GET
    @Path("/guest")
    @Produces("text/plain")
    public String helloGuest() throws RealmUnavailableException {
        return getPrintableInfo();
    }

    private String getPrintableInfo() throws RealmUnavailableException {
        Principal userPrincipal = securityContext.getUserPrincipal();
        String principalName = userPrincipal == null ? "anonymous" : userPrincipal.getName();
        SecurityIdentity identity = SecurityDomain.getCurrent().getCurrentSecurityIdentity();
        Attributes attributes = identity.getAttributes();
        StringBuilder printLines = new StringBuilder();
        for (String attribute : attributes.keySet()) {
            printLines.append(attribute).append(": ").append(attributes.get(attribute)).append("\n");
        }
        return "Hello " + principalName + "! " +
                "You have " + identity.getAttributes().size() + " attributes:\n\n" + printLines;
    }
}