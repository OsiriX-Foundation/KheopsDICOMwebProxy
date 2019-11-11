package online.kheops.proxy.part;

import online.kheops.proxy.id.ContentLocation;
import online.kheops.proxy.id.InstanceID;
import online.kheops.proxy.stream.TeeInputStream;
import org.dcm4che3.mime.MultipartInputStream;
import org.dcm4che3.ws.rs.MediaTypes;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.ext.Providers;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.function.Consumer;
import java.util.logging.Logger;

import static java.util.logging.Level.WARNING;
import static javax.ws.rs.core.HttpHeaders.*;
import static org.dcm4che3.ws.rs.MediaTypes.*;


public abstract class Part implements AutoCloseable {
    private static final Logger LOG = Logger.getLogger(Part.class.getName());

    private final Providers providers;

    private final MediaType mediaType;
    private final Path cacheFilePath;

    Part(final Providers providers, MediaType mediaType, Path cacheFilePath) {
        this.providers = providers;
        this.mediaType = mediaType;
        this.cacheFilePath = cacheFilePath;
    }

    public static Part getInstance(final MediaType contentType,
                                   final Providers providers,
                                   final MultipartInputStream multipartInputStream,
                                   final Consumer<String> fileID) throws IOException {
        final Map<String, List<String>> headerParams = multipartInputStream.readHeaderParams();
        final ContentLocation contentLocation = ContentLocation.valueOf(getHeaderParamValue(headerParams, CONTENT_LOCATION));
        final BufferedInputStream bufferedInputStream = new BufferedInputStream(multipartInputStream);

        final MediaType mediaType;
        if (contentType.isCompatible(MediaType.MULTIPART_FORM_DATA_TYPE)) {
            try {
                fileID.accept(getContentDispositionName(getHeaderParamValue(headerParams, CONTENT_DISPOSITION)));
            } catch (IllegalArgumentException e) {
                LOG.log(WARNING, "Unable to parse content-disposition: " + getHeaderParamValue(headerParams, CONTENT_DISPOSITION), e);
            }
            mediaType = APPLICATION_DICOM_TYPE;
        } else {
            mediaType = MediaType.valueOf(getHeaderParamValue(headerParams, CONTENT_TYPE));
        }

        final Path cacheFilePath = Files.createTempFile("PartCache", null);
        final Part newPart;
        try (final OutputStream outputStream = new BufferedOutputStream(Files.newOutputStream(cacheFilePath))) {
            if (MediaTypes.equalsIgnoreParameters(mediaType, APPLICATION_DICOM_TYPE)) {
                final TeeInputStream teeInputStream = new TeeInputStream(bufferedInputStream, outputStream);
                newPart = new DICOMPart(providers, teeInputStream, mediaType, cacheFilePath);
                teeInputStream.finish();
            } else if (MediaTypes.equalsIgnoreParameters(mediaType, APPLICATION_DICOM_XML_TYPE) || MediaTypes.equalsIgnoreParameters(mediaType, APPLICATION_DICOM_JSON_TYPE)) {
                final TeeInputStream teeInputStream = new TeeInputStream(bufferedInputStream, outputStream);
                newPart = new DICOMMetadataPart(providers, teeInputStream, mediaType, cacheFilePath);
                teeInputStream.finish();
            } else {
                newPart = new BulkDataPart(providers, bufferedInputStream, mediaType, contentLocation, cacheFilePath);
            }
            outputStream.flush();
        }
        return newPart;
    }

    protected Providers getProviders() {
        return providers;
    }

    /**
     * @param instanceID Returns Bulk Data locations for in the specified instance
     */
    public Set<ContentLocation> getBulkDataLocations(InstanceID instanceID) {
        return Collections.emptySet();
    }

    public Optional<ContentLocation> getContentLocation() {
        return Optional.empty();
    }

    public Set<InstanceID> getInstanceIDs() {
        return Collections.emptySet();
    }

    public MediaType getMediaType() {
        if (mediaType.equals(MediaType.valueOf("application/pdf"))) {
            return MediaType.valueOf("application/octet-stream");
        }
        if (mediaType.isCompatible(MediaType.valueOf("image/jpeg"))) {
            return MediaType.valueOf("image/jpeg; transfer-syntax=1.2.840.10008.1.2.4.50");
        }
        return mediaType;
    }

    private static String getHeaderParamValue(Map<String, List<String>> headerParams, String key) {
        List<String> list = headerParams.get(key);
        return list != null && !list.isEmpty() ? list.get(0) : null;
    }

    public void close() throws IOException {
        Files.delete(cacheFilePath);
    }

    public InputStream newInputStreamForInstance(Set<InstanceID> instanceIDs) throws IOException {
        if (instanceIDs.equals(getInstanceIDs())) {
            return Files.newInputStream(cacheFilePath);
        } else {
            throw new IllegalArgumentException("Requested instanceIDs don't match this Part's instanceIDs");
        }
    }

    private static String getContentDispositionName(final String contentDisposition) {
        // Horrible hack because DCM4CHE removes quotes from the headers for some really stupid reason
        // If this was not the case we could have used Jersey's ContentDisposition

        if (contentDisposition == null) {
            throw new IllegalArgumentException();
        }

        final int frontIndex = contentDisposition.indexOf("; name=");
        if (frontIndex == -1) {
            throw new IllegalArgumentException();
        }

        final String frontTrimmed = contentDisposition.substring(frontIndex + 7);
        final int backIndex = frontTrimmed.indexOf(';');
        if (backIndex == -1) {
            throw new IllegalArgumentException();
        }

        return frontTrimmed.substring(0, backIndex);
    }

    @Override
    public String toString() {
        final StringBuilder stringBuilder = new StringBuilder("Part InstanceIDs:");
        for (final InstanceID instanceID : getInstanceIDs()) {
            if (instanceID == null) {
                stringBuilder.append("unknown,");
            } else {
                stringBuilder.append(instanceID).append(",");
            }
        }
        return stringBuilder.toString();
    }
}
