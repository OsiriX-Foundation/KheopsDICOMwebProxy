package online.kheops.proxy.wadors;

import online.kheops.proxy.id.SeriesID;
import online.kheops.proxy.marshaller.JSONAttributesListMarshaller;
import online.kheops.proxy.tokens.AccessToken;
import online.kheops.proxy.tokens.AccessTokenException;
import online.kheops.proxy.tokens.AuthorizationToken;
import org.dcm4che3.data.Attributes;
import org.dcm4che3.data.Tag;
import org.dcm4che3.data.VR;

import javax.servlet.ServletContext;
import javax.ws.rs.*;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.*;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import static java.util.logging.Level.SEVERE;
import static java.util.logging.Level.WARNING;
import static javax.ws.rs.core.HttpHeaders.*;
import static javax.ws.rs.core.Response.Status.*;
import static org.dcm4che3.ws.rs.MediaTypes.APPLICATION_DICOM_JSON;

@Path("/")
public class WadoRSSeriesInstances {
    private static final Logger LOG = Logger.getLogger(WadoRSSeriesInstances.class.getName());
    private static final Client CLIENT = ClientBuilder.newClient().register(JSONAttributesListMarshaller.class);

    @Context
    UriInfo uriInfo;

    @Context
    ServletContext context;

    @HeaderParam(ACCEPT)
    String acceptParam;

    @HeaderParam(ACCEPT_CHARSET)
    String acceptCharsetParam;

    @GET
    @Path("password/dicomweb/studies/{StudyInstanceUID:([0-9]+[.])*[0-9]+}/series/{SeriesInstanceUID:([0-9]+[.])*[0-9]+}/instances")
    @Produces({"application/dicom+json;qs=1,multipart/related;type=\"application/dicom+xml\";qs=0.9,application/json;qs=0.8"})
    public Response wadoInstances(@PathParam("StudyInstanceUID") String studyInstanceUID,
                                  @PathParam("SeriesInstanceUID") String seriesInstanceUID,
                                  @HeaderParam(AUTHORIZATION) String authorizationHeader) {
        final URI authorizationURI = getParameterURI("online.kheops.auth_server.uri");
        final URI instanceQidoServiceURI = getParameterURI("online.kheops.pacs.uri");
        final URI rootURI = getParameterURI("online.kheops.root.uri");
        final MultivaluedMap<String, String> queryParameters = uriInfo.getQueryParameters();

        final AccessToken accessToken;
        try {
            accessToken = AccessToken.createBuilder(authorizationURI)
                    .withCapability(AuthorizationToken.fromAuthorizationHeader(authorizationHeader).getToken())
                    .withSeriesID(new SeriesID(studyInstanceUID, seriesInstanceUID))
                    .build();
        } catch (AccessTokenException e) {
            LOG.log(WARNING, "Unable to get an access token", e);
            throw new NotAuthorizedException("Bearer", "Basic");
        } catch (Exception e) {
            LOG.log(SEVERE, "unknown error while getting an access token", e);
            throw new InternalServerErrorException("unknown error while getting an access token");
        }

        WebTarget webTarget = CLIENT.target(instanceQidoServiceURI)
                .path("/studies/{StudyInstanceUID}/series/{SeriesInstanceUID}/instances")
                .resolveTemplate("StudyInstanceUID", studyInstanceUID)
                .resolveTemplate("SeriesInstanceUID", seriesInstanceUID);
        for (Map.Entry<String, List<String>> parameter: queryParameters.entrySet()) {
            webTarget = webTarget.queryParam(parameter.getKey(), parameter.getValue().toArray());
        }

        Invocation.Builder invocationBuilder = webTarget.request();
        invocationBuilder.header(AUTHORIZATION, accessToken.getHeaderValue());
        invocationBuilder.header(ACCEPT, APPLICATION_DICOM_JSON);
        if (acceptCharsetParam != null) {
            invocationBuilder.header(ACCEPT_CHARSET, acceptCharsetParam);
        }

        final List<Attributes> attributes;
        try {
            attributes = invocationBuilder.get(new GenericType<List<Attributes>>(){});
        } catch (ProcessingException e) {
            LOG.log(SEVERE, "error processing response from upstream", e);
            throw new WebApplicationException(BAD_GATEWAY);
        } catch (WebApplicationException e) {
            LOG.log(SEVERE, "error getting instances from upstream", e);
            throw new WebApplicationException(BAD_GATEWAY);
        } catch (Exception e) {
            LOG.log(SEVERE, "unknown error while getting from upstream", e);
            throw new InternalServerErrorException("unknown error while getting from upstream");
        }

        UriBuilder retrieveULRBuilder = UriBuilder.fromUri(rootURI).path("/api/studies/{StudyInstanceUID}/series/{SeriesInstanceUID}/instances/{SOPInstanceUID}");

        for (final Attributes instanceAttributes: attributes) {
            instanceAttributes.remove(Tag.RetrieveURL);
            String retrieveURL = retrieveULRBuilder.build(studyInstanceUID,seriesInstanceUID, instanceAttributes.getString(Tag.SOPInstanceUID)).toString();
            instanceAttributes.setString(Tag.RetrieveURL, VR.UI, retrieveURL);
        }

        final CacheControl cacheControl = new CacheControl();
        cacheControl.setNoCache(true);

        GenericEntity<List<Attributes>> list = new GenericEntity<List<Attributes>>(attributes) {};
        return Response.ok(list)
                .cacheControl(cacheControl)
                .build();
    }

    private URI getParameterURI(String parameter) {
        try {
            return new URI(context.getInitParameter(parameter));
        } catch (URISyntaxException e) {
            LOG.log(SEVERE, e, () -> "Error with " + parameter);
            throw new WebApplicationException(INTERNAL_SERVER_ERROR);
        }
    }
}