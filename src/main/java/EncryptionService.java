import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Base64;
import java.util.Properties;

/**
 * @author s4dad\potolal
 */
public class EncryptionService extends AbstractService {

    /* ---- Constants ---- */

    private static final String ENCRYPTION_PROPERTIES_FILE_NAME = "encryption.properties";


    /* ---- Instance Variables ---- */


    /* ---- Constructors ---- */


    /* ---- Business methods ---- */

    public String signAndEncrypt(String message) throws IOException {

        Properties properties = this.loadEncryptionProperties();
        String contentOfCertificateUsedForEncryption = this.retrieveContentOfCertificateUsedForEncryption(properties.getProperty("certificate.name"));
        ASiCService aSiCService = super.getAsicService(properties);
        ByteArrayOutputStream baos = aSiCService.signAndEncrypt(message, contentOfCertificateUsedForEncryption);
        String encryptedMessageAsBase64String = Base64.getEncoder().encodeToString(baos.toByteArray());

        return encryptedMessageAsBase64String;
    }

    private Properties loadEncryptionProperties() {

        return super.loadProperties(ENCRYPTION_PROPERTIES_FILE_NAME);
    }

    private String retrieveContentOfCertificateUsedForEncryption(String certificateFileName)  {

        return super.retrieveCertificateContentAsString(certificateFileName);
    }


    /* ---- Getters and Setters ---- */
}
