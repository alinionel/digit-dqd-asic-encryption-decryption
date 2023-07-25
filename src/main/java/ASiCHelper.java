import no.difi.asic.AsicReader;
import no.difi.asic.AsicWriter;
import no.difi.asic.AsicWriterFactory;
import no.difi.asic.extras.CmsEncryptedAsicReader;
import no.difi.asic.extras.CmsEncryptedAsicWriter;
import no.difi.commons.asic.jaxb.asic.Certificate;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ASiCHelper {

    /* ---- Constants ---- */

    private static final String DEFAULT_BORIS_MESSAGE_FILENAME = "BORIS-Message.xml";
    private static final String DEFAULT_BRIS_DQD_MESSAGE_FILENAME = "BRIS-DQd-Message.xml";


    /* ---- Instance Variables ---- */

    private KeyStoreHelper keyStoreHelper;


    /* ---- Constructors ---- */

    public ASiCHelper(KeyStoreHelper keyStoreHelper) {
        this.keyStoreHelper = keyStoreHelper;
    }


    /* ---- Business Methods ---- */

    /**
        @param xmlMessage the message to send
        @param recipientCertificate recipient certificate used for encrypting the message
     */
    public ByteArrayOutputStream generateASiCEContainerToSend(String xmlMessage, X509Certificate recipientCertificate) {

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

        try {

            AsicWriter asicWriter = AsicWriterFactory.newFactory().newContainer(byteArrayOutputStream);

            // Create the ASiC-E container writer
            CmsEncryptedAsicWriter writer = new CmsEncryptedAsicWriter(asicWriter, recipientCertificate);

            // add the XML Message to the ASiC-E Container
            InputStream messageInputStream = new ByteArrayInputStream(xmlMessage.getBytes(Charset.forName("UTF-8")));
            writer.addEncrypted(messageInputStream, DEFAULT_BRIS_DQD_MESSAGE_FILENAME);
            // important step in order to distinguish the BORIS XML Message from the other files in the container (attachments)
            writer.setRootEntryName(DEFAULT_BRIS_DQD_MESSAGE_FILENAME);

            // Sign the ASiC-E container using the private key of the sender
            writer.sign(keyStoreHelper.getSignatureHelper());
        } catch (Exception exception) {
            throw new RuntimeException(exception);
        }

        return byteArrayOutputStream;
    }

    public Map<String, ByteArrayOutputStream> readAsicContainer(CmsEncryptedAsicReader reader) throws IOException {
        Map<String, ByteArrayOutputStream> result = new HashMap<>();
        // Important note: read ASiC-E Container until the end
        // => this will trigger the signature validation to complete
        String nextFile;
        while ((nextFile = reader.getNextFile())!= null) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            reader.writeFile(baos);

            result.put(nextFile, baos);
        }

        return result;
    }

    public boolean isSenderCertificateValid(AsicReader reader, X509Certificate senderCertificateFromIKAR) throws CertificateEncodingException {
        boolean result = false;

        List<Certificate> certificateList = reader.getAsicManifest().getCertificate();

        if (certificateList.size() == 1) {
            // only one receiver per message in the context of BORIS and DQD, so only one certificate is expected
            byte[] encodedSenderCertificateFromPayload = certificateList.get(0).getCertificate();
            byte[] encodedCertificateFromIKAR = senderCertificateFromIKAR.getEncoded();

            if (encodedSenderCertificateFromPayload.length == encodedCertificateFromIKAR.length) {
                // perform binary comparison of certificates
                boolean validationSuccess = true;
                for (int i = 0; i < encodedCertificateFromIKAR.length; i++) {
                    validationSuccess &= encodedSenderCertificateFromPayload[i] == encodedCertificateFromIKAR[i];

                    if (!validationSuccess) {
                        // stop the binary comparison as soon as there's a mismatch
                        break;
                    }
                }

                result |= validationSuccess;
            }
        }

        return result;
    }

    public X509Certificate convertStringToX509Cert(String certificate) throws CertificateException {
        InputStream targetStream = new ByteArrayInputStream(certificate.getBytes());
        return (X509Certificate) CertificateFactory
                .getInstance("X509")
                .generateCertificate(targetStream);
    }

    /* ---- Getters and Setters----*/

}
