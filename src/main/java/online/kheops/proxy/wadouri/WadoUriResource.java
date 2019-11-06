package online.kheops.proxy.wadouri;

import online.kheops.proxy.id.SeriesID;
import online.kheops.proxy.tokens.AccessToken;
import online.kheops.proxy.tokens.AccessTokenException;
import online.kheops.proxy.tokens.AuthorizationToken;
import org.dcm4che3.mime.MultipartInputStream;
import org.dcm4che3.mime.MultipartParser;

import javax.servlet.ServletContext;
import javax.ws.rs.*;
import javax.ws.rs.client.*;
import javax.ws.rs.core.*;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.logging.Logger;

import static java.util.logging.Level.SEVERE;
import static java.util.logging.Level.WARNING;
import static javax.ws.rs.core.HttpHeaders.*;
import static javax.ws.rs.core.Response.Status.*;
import static org.dcm4che3.ws.rs.MediaTypes.APPLICATION_DICOM;
import static org.glassfish.jersey.media.multipart.Boundary.BOUNDARY_PARAMETER;

@Path("/")
public class WadoUriResource {
    private static final Logger LOG = Logger.getLogger(WadoUriResource.class.getName());

    private static final Client CLIENT = ClientBuilder.newClient();

    @Context
    UriInfo uriInfo;

    @Context
    ServletContext context;

    @HeaderParam(ACCEPT)
    String acceptParam;

    @HeaderParam(ACCEPT_CHARSET)
    String acceptCharsetParam;

    @GET
    @Path("/password/dicomweb/wado")
    public Response wado(@HeaderParam(AUTHORIZATION) String authorizationHeader) {
        return webAccess(AuthorizationToken.fromAuthorizationHeader(authorizationHeader));
    }

    @GET
    @Path("/{capability:[a-zA-Z0-9]{22}}/dicomweb/wado")
    public Response wadoWithCapability(@PathParam("capability") String capabilityToken) {
        return webAccess(AuthorizationToken.from(capabilityToken));
    }

    private Response webAccess(AuthorizationToken authorizationToken) {
        final URI authorizationURI = getParameterURI("online.kheops.auth_server.uri");
        final URI serviceURI = getParameterURI("online.kheops.pacs.uri");

        final MultivaluedMap<String, String> queryParameters = uriInfo.getQueryParameters();

        final List<String> studyInstanceUIDs = queryParameters.get("studyUID");
        if (studyInstanceUIDs == null || studyInstanceUIDs.size() != 1) {
            LOG.log(WARNING, "Missing studyUID");
            throw new BadRequestException("Missing studyUID");
        }
        final List<String> seriesInstanceUIDs = queryParameters.get("seriesUID");
        if (seriesInstanceUIDs == null || seriesInstanceUIDs.size() != 1) {
            LOG.log(WARNING, "Missing seriesUID");
            throw new BadRequestException("Missing seriesUID");
        }

        final List<String> sopInstanceUIDs = queryParameters.get("objectUID");
        if (sopInstanceUIDs == null || sopInstanceUIDs.size() != 1) {
            LOG.log(WARNING, "Missing objectUID");
            throw new BadRequestException("Missing objectUID");
        }

        final String studyInstanceUID = studyInstanceUIDs.get(0);
        final String seriesInstanceUID = seriesInstanceUIDs.get(0);
        final String sopInstanceUID = sopInstanceUIDs.get(0);

        final AccessToken accessToken;
        try {
            accessToken = AccessToken.createBuilder(authorizationURI)
                    .withClientId(context.getInitParameter("online.kheops.client.dicomwebproxyclientid"))
                    .withClientSecret(context.getInitParameter("online.kheops.client.dicomwebproxysecret"))
                    .withCapability(authorizationToken.getToken())
                    .withSeriesID(new SeriesID(studyInstanceUID, seriesInstanceUID))
                    .build();
        } catch (AccessTokenException e) {
            LOG.log(WARNING, "Unable to get an access token", e);
            throw new NotAuthorizedException("Bearer", "Basic");
        } catch (Exception e) {
            LOG.log(SEVERE, "unknown error while getting an access token", e);
            throw new InternalServerErrorException("unknown error while getting an access token");
        }

        final WebTarget webTarget = CLIENT.target(serviceURI)
                .path("/studies/{StudyInstanceUID}/series/{SeriesInstanceUID}/instances/{SOPInstanceUID}")
                .resolveTemplate("StudyInstanceUID", studyInstanceUID)
                .resolveTemplate("SeriesInstanceUID", seriesInstanceUID)
                .resolveTemplate("SOPInstanceUID", sopInstanceUID);

        Invocation.Builder invocationBuilder = webTarget.request();
        invocationBuilder.header(AUTHORIZATION, accessToken.getHeaderValue());

        StreamingOutput streamingOutput = output -> {
            MultipartParser.Handler handler = (int partNumber, MultipartInputStream in) -> {
                if (partNumber != 1) {
                    LOG.log(SEVERE, "Unexpected part number:" + partNumber);
                    throw new IOException("Unexpected part number:" + partNumber);
                }

                in.readHeaderParams();

                byte[] buffer = new byte[4096];
                int len = in.read(buffer);
                while (len != -1) {
                    output.write(buffer, 0, len);
                    len = in.read(buffer);
                }
            };

            try (final Response wadoRSResponse = webTarget.request().header(AUTHORIZATION, accessToken.getHeaderValue()).get()) {
                final String boundary = MediaType.valueOf(wadoRSResponse.getHeaderString(CONTENT_TYPE)).getParameters().get(BOUNDARY_PARAMETER);
                try (final InputStream inputStream = new BufferedInputStream(wadoRSResponse.readEntity(InputStream.class))) {
                    new MultipartParser(boundary).parse(inputStream, handler);
                }
            } catch (ResponseProcessingException e) {
                LOG.log(SEVERE, "ResponseProcessingException status:" + e.getResponse().getStatus(), e);
                throw new IOException(e);
            } catch (ProcessingException e) {
                LOG.log(SEVERE, "ProcessingException:", e);
                throw new IOException(e);
            }
            output.flush();
        };

        return Response.ok(streamingOutput).type(APPLICATION_DICOM).build();
    }

    private URI getParameterURI(String parameter) {
        try {
            return new URI(context.getInitParameter(parameter));
        } catch (URISyntaxException e) {
            LOG.log(SEVERE, "Error with the STOWServiceURI", e);
            throw new WebApplicationException(INTERNAL_SERVER_ERROR);
        }
    }
}


