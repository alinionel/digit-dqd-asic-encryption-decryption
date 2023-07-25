import no.difi.asic.AsicReader;
import no.difi.asic.AsicReaderFactory;
import no.difi.asic.extras.CmsEncryptedAsicReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

public class ASiCService {

    /* ---- Constants ---- */

    public final Logger logger = LoggerFactory.getLogger(getClass());

    /* ---- Instance Variables ---- */

    private KeyStoreHelper keyStoreHelper;

    private ASiCHelper aSicHelper;

    /* ---- Constructors ---- */

    public ASiCService(KeyStoreHelper keyStoreHelper, ASiCHelper aSicHelper) {
        this.keyStoreHelper = keyStoreHelper;
        this.aSicHelper = aSicHelper;
    }

    /* ---- Business Methods ---- */

    public String validateAndDecrypt(ByteArrayInputStream asicContainer, String senderCertificateContentAsString) {

        Map<String, String> messageContentMap = new HashMap<>();

        try {

            X509Certificate senderCertificate = aSicHelper.convertStringToX509Cert(senderCertificateContentAsString);

            AsicReader asicReader = AsicReaderFactory.newFactory().open(asicContainer);

            PrivateKey privateKey = keyStoreHelper.getPrivateKey();

            CmsEncryptedAsicReader reader = new CmsEncryptedAsicReader(asicReader, privateKey);
            // get all files from the container
            Map<String, ByteArrayOutputStream> fileMap = aSicHelper.readAsicContainer(reader);

            // Validate attached certificate: it should match the certificate attached to the supposed sender received from IKAR
            if (aSicHelper.isSenderCertificateValid(reader, senderCertificate)) {

                logger.info("Sender certificate is valid");

                String rootFileName = reader.getAsicManifest().getRootfile();

                for (String entryName : fileMap.keySet()) {

                    if (entryName.equals(rootFileName)) {
                        // the current entry is the actual XML message
                        messageContentMap.put("message", new String(fileMap.get(entryName).toByteArray(), StandardCharsets.UTF_8));
                    } else {
                        // the current entry is an attachment
                        // the entry name is the attachment reference mentioned in the BORIS XML message
                        messageContentMap.put("attachment", new String(fileMap.get(entryName).toByteArray(), StandardCharsets.UTF_8));
                    }
                }
            } else {
                // handle validation error
                throw new RuntimeException("Invalid bundled sender certificate in ASiC-E container");
            }
        } catch (Exception e) {
            throw new RuntimeException("Validation and decryption of Asic container failed", e);
        }

        return messageContentMap.get("message");
    }

    public ByteArrayOutputStream signAndEncrypt(String message, String certificateContentAsString) {

        X509Certificate certificateForEncryption = null;

        try {
            certificateForEncryption = aSicHelper.convertStringToX509Cert(certificateContentAsString);
        } catch (CertificateException e) {
            e.printStackTrace();
        }

        return aSicHelper.generateASiCEContainerToSend(message, certificateForEncryption);
    }

    /* ---- Getters and Setters----*/

}
