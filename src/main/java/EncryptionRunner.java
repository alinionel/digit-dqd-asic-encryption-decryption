import java.io.IOException;

/**
 * @author s4dad\potolal
 */
public class EncryptionRunner {

    /* ---- Constants ---- */


    /* ---- Instance Variables ---- */


    /* ---- Constructors ---- */


    /* ---- Business methods ---- */

    public static void main(String[] args) throws IOException {

        EncryptionService encryptionService = new EncryptionService();
//        String inputMessageString = "<ConnectivityRequest xmlns=\"http://ec.europa.eu/boris/v1_0/ConnectivityRequest\" xmlns:bbc=\"http://ec.europa.eu/boris/v1_0/common/BasicComponents\"><bbc:SendingDateTime>2022-02-03T17:45:37.455+01:00</bbc:SendingDateTime></ConnectivityRequest>";

        String inputMessageString = "<BR-ConnectivityResponse xmlns=\"http://ec.europa.eu/bris/v5_0/br/ConnectivityResponse\" xmlns:bbc=\"http://ec.europa.eu/bris/v1_4/common/BasicComponents\"><bbc:SendingDateTime>2023-07-25T09:22:02.242Z</bbc:SendingDateTime></BR-ConnectivityResponse>";

//        String encryptedContent = encryptionService.signAndEncrypt("<ConnectivityRequest xmlns=\"http://ec.europa.eu/boris/v1_0/ConnectivityRequest\" xmlns:bbc=\"http://ec.europa.eu/boris/v1_0/common/BasicComponents\">\n" +
//                "    <bbc:SendingDateTime>2021-09-24T13:42:00.000Z</bbc:SendingDateTime>\n" +
//                "</ConnectivityRequest>");

        String encryptedContent = encryptionService.signAndEncrypt(inputMessageString);

        System.out.println(String.format("CONTENT BEFORE ENCRYPTION: %s", inputMessageString));

        System.out.println(String.format("ENCRYPTED CONTENT: %s", encryptedContent));
    }



    /* ---- Getters and Setters ---- */
}
