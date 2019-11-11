package online.kheops.proxy.part;

import online.kheops.proxy.id.ContentLocation;
import online.kheops.proxy.id.InstanceID;
import org.dcm4che3.data.Attributes;
import org.dcm4che3.data.BulkData;
import org.dcm4che3.data.Tag;
import org.dcm4che3.data.VR;
import org.dcm4che3.io.SAXReader;
import org.dcm4che3.ws.rs.MediaTypes;
import org.xml.sax.SAXException;

import javax.ws.rs.core.*;
import javax.ws.rs.ext.MessageBodyReader;
import javax.ws.rs.ext.MessageBodyWriter;
import javax.ws.rs.ext.Providers;
import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.annotation.Annotation;
import java.nio.file.Path;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

class DICOMMetadataPart extends Part {
    private static final Logger LOG = Logger.getLogger(DICOMMetadataPart.class.getName());

    private static final Annotation[] EMPTY_ANNOTATIONS = new Annotation[0];

    private final Set<Attributes> datasets;
    private final Map<InstanceID, Set<ContentLocation>> bulkDataLocations;

    private final Set<InstanceID> instanceIDs;

    DICOMMetadataPart(final Providers providers, final InputStream inputStream, final MediaType mediaType, final Path cacheFilePath) throws IOException {
        super(providers, mediaType, cacheFilePath);

        if (MediaTypes.equalsIgnoreParameters(mediaType, MediaTypes.APPLICATION_DICOM_XML_TYPE)) {
            try {
                datasets = Collections.singleton(SAXReader.parse(inputStream));
            } catch (ParserConfigurationException | SAXException e) {
                throw new IOException("Unable to read DICOM XML", e);
            }
        } else if (MediaTypes.equalsIgnoreParameters(mediaType, MediaTypes.APPLICATION_DICOM_JSON_TYPE)) {
            datasets = readJSONAttributes(inputStream);
        } else {
            throw new IllegalArgumentException("Invalid Media Type");
        }

        for (final Attributes attributes: datasets) {
            LOG.log(Level.SEVERE, "Adding specific characterset");
            attributes.setString(Tag.SpecificCharacterSet, VR.CS, "ISO_IR 192");
            if (attributes.getString(Tag.Modality, "").equals("XC")) {
                LOG.log(Level.SEVERE, "Adding jpeg syntax");
                attributes.setString(Tag.TransferSyntaxUID, VR.UI, "1.2.840.10008.1.2.4.50");
            } else {
                attributes.setString(Tag.TransferSyntaxUID, VR.UI, "1.2.840.10008.1.2.1");
            }
        }

        try {
            bulkDataLocations = parseBulkDataLocations(datasets);
        } catch (Exception e) {
            throw new IOException("Error while parsing for Bulk Data", e);
        }

        instanceIDs = readInstanceIDs();
    }

    DICOMMetadataPart(final Providers providers, final Set<Attributes> datasets, final MediaType mediaType, final Path cacheFilePath) throws IOException {
        super(providers, mediaType, cacheFilePath);
        this.datasets = datasets;
        this.bulkDataLocations = Collections.emptyMap();
        instanceIDs = readInstanceIDs();
    }

    @Override
    public Set<InstanceID> getInstanceIDs() {
        return instanceIDs;
    }

    @Override
    public InputStream newInputStreamForInstance(Set<InstanceID> instanceIDs) throws IOException {
        if (instanceIDs.equals(getInstanceIDs())) {
            return super.newInputStreamForInstance(instanceIDs);
        } else if (MediaTypes.equalsIgnoreParameters(getMediaType(), MediaTypes.APPLICATION_DICOM_JSON_TYPE)) {
            return new ByteArrayInputStream(getBytesForInstances(instanceIDs));
        } else {
            throw new IllegalArgumentException("Requesting an inexact set of instances for a mediatype other than JSON");
        }
    }

    private static Map<InstanceID, Set<ContentLocation>> parseBulkDataLocations(Set<Attributes> datasets) throws Exception {
        Map<InstanceID, Set<ContentLocation>> bulkDataLocationsMap = new HashMap<>();

        for (Attributes dataset : datasets) {
            Set<ContentLocation> bulkDataLocations = new HashSet<>();
            bulkDataLocationsMap.put(InstanceID.from(dataset), bulkDataLocations);
            dataset.accept((attrs, tag, vr, value) -> {
                if (value instanceof BulkData) {
                    bulkDataLocations.add(ContentLocation.valueOf(((BulkData) value).getURI()));
                }
                return true;
            }, true);
        }

        return bulkDataLocationsMap;
    }

    private Set<Attributes> readJSONAttributes(InputStream inputStream) throws IOException {
        final GenericType<List<Attributes>> genericType = new GenericType<List<Attributes>>() {
        };
        final MessageBodyReader<List> bodyReader = getProviders().getMessageBodyReader(
                List.class,
                genericType.getType(),
                EMPTY_ANNOTATIONS,
                MediaTypes.APPLICATION_DICOM_JSON_TYPE);

        if (bodyReader == null) {
            throw new IllegalArgumentException("Could not get a MessageBodyReader for List<Attributes>");
        }

        List<?> attributesList = bodyReader.readFrom(
                List.class,
                genericType.getType(),
                EMPTY_ANNOTATIONS,
                MediaTypes.APPLICATION_DICOM_JSON_TYPE,
                new MultivaluedHashMap<>(),
                inputStream);

        return attributesList.stream()
                .map(attributes -> {
                    if (attributes instanceof Attributes) {
                        return (Attributes) attributes;
                    } else {
                        throw new IllegalArgumentException("Not Arguments encoded");
                    }
                }).collect(Collectors.toSet());
    }

    private List<Attributes> getAttributesListForInstances(Set<InstanceID> requestedInstanceIDs) throws IOException {
        Set<InstanceID> partInstanceIDs = getInstanceIDs();
        if (requestedInstanceIDs.stream().anyMatch(instanceID -> !partInstanceIDs.contains(instanceID))) {
            throw new IOException("Requesting instances that are not in this Part");
        }
        return datasets.stream()
                .filter(attributes -> requestedInstanceIDs.contains(InstanceID.from(attributes)))
                .collect(Collectors.toList());
    }

    private byte[] getBytesForInstances(Set<InstanceID> instanceIDs) throws IOException {
        final GenericType<List<Attributes>> genericType = new GenericType<List<Attributes>>() { };

        try (final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()) {
            final MessageBodyWriter<List> bodyWriter = getProviders().getMessageBodyWriter(
                    List.class,
                    genericType.getType(),
                    EMPTY_ANNOTATIONS,
                    MediaTypes.APPLICATION_DICOM_JSON_TYPE);

            if (bodyWriter == null) {
                throw new IllegalArgumentException("Could not get a MessageBodyWriter for List<Attributes>");
            }

            bodyWriter.writeTo(
                    getAttributesListForInstances(instanceIDs),
                    List.class,
                    genericType.getType(),
                    EMPTY_ANNOTATIONS,
                    MediaTypes.APPLICATION_DICOM_JSON_TYPE,
                    new MultivaluedHashMap<>(),
                    byteArrayOutputStream);

            return byteArrayOutputStream.toByteArray();
        }
    }

    @Override
    public Set<ContentLocation> getBulkDataLocations(final InstanceID instanceID) {
        return bulkDataLocations.getOrDefault(instanceID, Collections.emptySet());
    }

    private Set<InstanceID> readInstanceIDs() throws IOException {
        try {
            return datasets.stream().map(InstanceID::from).collect(Collectors.toSet());
        } catch (IllegalArgumentException e) {
            throw new IOException("Error while parsing instanceIDs", e);
        }
    }
}
