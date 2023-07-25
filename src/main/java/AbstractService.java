import java.io.*;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.util.Properties;


/**
 * @author s4dad\potolal
 */
public abstract class AbstractService {

    /* ---- Constants ---- */

    private static final String KEY_STORE_NAME_PROPERTY = "keyStore.name";
    private static final String KEY_STORE_PASSWORD_PROPERTY = "keyStore.password";
    private static final String KEY_STORE_KEY_PAIR_ALIAS_PROPERTY = "keyStore.key.alias";
    private static final String KEY_STORE_PRIVATE_KEY_PASSWORD_PROPERTY = "keyStore.privateKey.password";


    /* ---- Instance Variables ---- */


    /* ---- Constructors ---- */


    /* ---- Business methods ---- */

    protected ASiCService getAsicService(Properties properties) {

        KeyStoreHelper keyStoreHelper = this.getKeyStoreHelper(properties);

        return new ASiCService(keyStoreHelper, this.getAsicHelper(keyStoreHelper));
    }

    protected ASiCHelper getAsicHelper(KeyStoreHelper keyStoreHelper) {

        return new ASiCHelper(keyStoreHelper);
    }

    protected KeyStoreHelper getKeyStoreHelper(Properties prop) {
        String keystorePath = Thread.currentThread().getContextClassLoader().getResource("").getPath() + prop.getProperty(KEY_STORE_NAME_PROPERTY);
        String ksPwd = prop.getProperty(KEY_STORE_PASSWORD_PROPERTY);
        String keyAlias = prop.getProperty(KEY_STORE_KEY_PAIR_ALIAS_PROPERTY);
        String privateKeyPwd = prop.getProperty(KEY_STORE_PRIVATE_KEY_PASSWORD_PROPERTY);

        return new KeyStoreHelper(keystorePath, ksPwd, privateKeyPwd, keyAlias);

    }

    protected Properties loadProperties(String propertiesFileName) {
        String applicationPropertiesPath = Thread.currentThread().getContextClassLoader().getResource("").getPath() + propertiesFileName;
        InputStream input = null;

        try {
            input = new FileInputStream(applicationPropertiesPath);
        } catch (FileNotFoundException e) {
            throw new RuntimeException(String.format("Issue loading %s at: %s", propertiesFileName, applicationPropertiesPath) , e);
        }

        Properties prop = new Properties();

        try {
            prop.load(input);
        } catch (IOException e) {
            throw new RuntimeException(String.format("Issue loading %s at: %s", propertiesFileName, applicationPropertiesPath) , e);
        }
        return prop;
    }

    protected String retrieveCertificateContentAsString(String certificateFileName)  {
        File certificateFile = new File(Thread.currentThread().getContextClassLoader().getResource("").getPath() + certificateFileName);

        try {
            String retrievedCertificateContent = new String(Files.readAllBytes(certificateFile.toPath()), Charset.defaultCharset());

            return this.sanitizeCertificate(retrievedCertificateContent);
        } catch (IOException e) {
            throw new RuntimeException("Issue loading " + certificateFileName + " file at: " + certificateFile.toPath(), e);
        }
    }

//    private static String removeAllNewLines(String text) {
//
//        String textWithoutLineFeeds = StringUtils.remove(text, "\n");
//
//        return StringUtils.remove(textWithoutLineFeeds, "\r");
//    }

    private static String sanitizeCertificate(String text) {

        return text.replace("\\r\\n", System.lineSeparator()).replace("\\n", System.lineSeparator()).replace("\\r", System.lineSeparator());
    }

    /* ---- Getters and Setters ---- */
}
