import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;

public class KeyStoreHelper {

    /* ---- Constants ---- */

    /* ---- Instance Variables ---- */

    private String keystorePath;

    private String keyStorePassword;

    private String privateKeyPassword;

    private String alias;

    /* ---- Constructors ---- */
    KeyStoreHelper(String keystorePath, String keyStorePassword, String privateKeyPassword, String alias) {
        this.keystorePath = keystorePath;
        this.keyStorePassword = keyStorePassword;
        this.privateKeyPassword = privateKeyPassword;
        this.alias = alias;
    }

    /* ---- Business Methods ---- */

    public PrivateKey getPrivateKey() {
        KeyStore keystore = loadKeystore();
        KeyStore.PrivateKeyEntry entry = null;

        try {
            entry = (KeyStore.PrivateKeyEntry)keystore.getEntry(alias ,new KeyStore.PasswordProtection(privateKeyPassword.toCharArray()));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        return entry.getPrivateKey();
    }

    public SignatureHelper getSignatureHelper() {
        return new SignatureHelper(loadKeystore(), keyStorePassword, alias, privateKeyPassword);
    }

    private KeyStore loadKeystore() {

        KeyStore keystore = null;

        try {
            keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        try {
            InputStream inputStream = new FileInputStream(keystorePath);
            keystore.load(inputStream, keyStorePassword.toCharArray());
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        return keystore;
    }


    /* ---- Getters and Setters----*/

}
