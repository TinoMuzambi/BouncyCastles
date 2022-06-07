import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Base64;

public class ClientRunner {
    public static void main(String[] args) throws GeneralSecurityException {
        System.setProperty("org.bouncycastle.rsa.allow_multi_use", "true");
        Hashing.installProvider();
        KeyPair pair = Hashing.generateKeyPair();
        String[] keys = {Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()), Base64.getEncoder().encodeToString(pair.getPublic().getEncoded())};
        Client.main(keys);
    }
}
