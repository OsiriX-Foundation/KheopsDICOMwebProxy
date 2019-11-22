package online.kheops.proxy.wadouri;

import online.kheops.proxy.id.SeriesID;
import online.kheops.proxy.tokens.AccessToken;
import online.kheops.proxy.tokens.AccessTokenException;
import online.kheops.proxy.tokens.AuthorizationToken;
import org.dcm4che3.ws.rs.MediaTypes;

import javax.servlet.ServletContext;
import javax.ws.rs.*;
import javax.ws.rs.client.*;
import javax.ws.rs.core.*;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static java.util.logging.Level.SEVERE;
import static java.util.logging.Level.WARNING;
import static javax.ws.rs.core.HttpHeaders.*;
import static javax.ws.rs.core.Response.Status.*;

@Path("/")
public class WadoUriResource {
    private static final Logger LOG = LoggerFactory.getLogger(WadoUriResource.class);

    private static final Client CLIENT = ClientBuilder.newClient();

    private static final String HEADER_X_FORWARDED_FOR = "X-Forwarded-For";

    @Context
    UriInfo uriInfo;

    @Context
    ServletContext context;

    @HeaderParam(ACCEPT)
    String acceptParam;

    @HeaderParam(ACCEPT_CHARSET)
    String acceptCharsetParam;

    @HeaderParam(HEADER_X_FORWARDED_FOR)
    String headerXForwardedFor;

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

    final static AtomicInteger closeCounter = new AtomicInteger();

    private Response webAccess(AuthorizationToken authorizationToken) {
        final URI authorizationURI = getParameterURI("online.kheops.auth_server.uri");
        URI wadoServiceURI = getParameterURI("online.kheops.pacs.uri");

        WebTarget webTarget = CLIENT.target(wadoServiceURI).path("wado");

        final MultivaluedMap<String, String> queryParameters = uriInfo.getQueryParameters();

        final List<String> studyInstanceUIDs = queryParameters.get("studyUID");
        if (studyInstanceUIDs == null || studyInstanceUIDs.size() != 1) {
            throw new WebApplicationException(BAD_REQUEST);
        }
        final List<String> seriesInstanceUIDs = queryParameters.get("seriesUID");
        if (seriesInstanceUIDs == null || seriesInstanceUIDs.size() != 1) {
            throw new WebApplicationException(BAD_REQUEST);
        }

        final String studyInstanceUID = studyInstanceUIDs.get(0);
        final String seriesInstanceUID = seriesInstanceUIDs.get(0);

        final AccessToken accessToken;
        try {
            accessToken = AccessToken.createBuilder(authorizationURI)
                    .withClientId(context.getInitParameter("online.kheops.client.dicomwebproxyclientid"))
                    .withClientSecret(context.getInitParameter("online.kheops.client.dicomwebproxysecret"))
                    .withCapability(authorizationToken.getToken())
                    .withSeriesID(new SeriesID(studyInstanceUID, seriesInstanceUID))
                    .xForwardedFor(headerXForwardedFor)
                    .build();
        } catch (AccessTokenException e) {
            LOG.warn("Unable to get an access token", e);
            throw new NotAuthorizedException("Bearer", "Basic");
        } catch (Exception e) {
            LOG.error("unknown error while getting an access token", e);
            throw new InternalServerErrorException("unknown error while getting an access token");
        }

        for (Map.Entry<String, List<String>> parameter: queryParameters.entrySet()) {
            webTarget = webTarget.queryParam(parameter.getKey(), parameter.getValue().toArray());
        }

        Invocation.Builder invocationBuilder = webTarget.request();
        invocationBuilder.header(AUTHORIZATION, accessToken.getHeaderValue());
        if (acceptParam != null) {
            invocationBuilder.accept(acceptParam);
        } else {
            invocationBuilder.accept(MediaTypes.APPLICATION_DICOM);
        }

        if (acceptCharsetParam != null) {
            invocationBuilder.header(ACCEPT_CHARSET, acceptCharsetParam);
        }

        final Response upstreamResponse;
        try {
            upstreamResponse = invocationBuilder.get();
            LOG.error("closeCounter: {}", closeCounter.getAndIncrement());
        } catch (ProcessingException e) {
            LOG.error("error processing response from upstream", e);
            throw new WebApplicationException(BAD_GATEWAY);
        } catch (Exception e) {
            LOG.error("unknown error while getting from upstream", e);
            throw new InternalServerErrorException("unknown error while getting from upstream");
        }

        if (upstreamResponse.getStatusInfo().getFamily() == Family.SERVER_ERROR) {
            LOG.warn("Sever error from upstream: status {}", upstreamResponse.getStatus());
            throw new WebApplicationException(BAD_GATEWAY);
        }

        StreamingOutput streamingOutput = output -> {
            try (final InputStream inputStream = upstreamResponse.readEntity(InputStream.class)) {
                byte[] buffer = new byte[4096];
                int len = inputStream.read(buffer);
                while (len != -1) {
                    output.write(buffer, 0, len);
                    len = inputStream.read(buffer);
                }
            } catch (Exception e) {
                throw new IOException(e);
            } finally {
                upstreamResponse.close();
                closeCounter.decrementAndGet();
            }
        };

        final CacheControl cacheControl = new CacheControl();
        cacheControl.setNoCache(true);

        return Response.status(upstreamResponse.getStatus()).entity(streamingOutput)
                .header(CONTENT_TYPE, upstreamResponse.getHeaderString(CONTENT_TYPE))
                .cacheControl(cacheControl)
                .build();
    }

    private URI getParameterURI(String parameter) {
        try {
            return new URI(context.getInitParameter(parameter));
        } catch (URISyntaxException e) {
            LOG.error("Error with the STOWServiceURI", e);
            throw new WebApplicationException(INTERNAL_SERVER_ERROR);
        }
    }
}


