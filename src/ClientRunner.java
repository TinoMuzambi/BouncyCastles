import java.security.GeneralSecurityException;
import java.security.KeyPair;

/**
 * Creates a key pair for a Client then runs a new instance of a Client passing in the key pair encoded.
 */
public class ClientRunner {

    /**
     * Main method which installs the BouncyCastle provider, generates a key pair for the client then runs the client passing through the key pair.
     * @param args Command line arguments.
     * @throws GeneralSecurityException Security errors.
     */
    public static void main(String[] args) throws GeneralSecurityException {
        System.setProperty("org.bouncycastle.rsa.allow_multi_use", "true");
        Utils.installProvider();
        KeyPair pair = Hashing.generateKeyPair();
        String[] keys = {Utils.encode(pair.getPrivate().getEncoded()), Utils.encode(pair.getPublic().getEncoded())};
        Client.main(keys);
    }
}
