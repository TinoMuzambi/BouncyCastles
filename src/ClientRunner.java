import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Arrays;

public class ClientRunner {
    public static void main(String[] args) throws GeneralSecurityException {
        Hashing.installProvider();
        KeyPair pair = Hashing.generateKeyPair();
        String[] keys = {Arrays.toString(pair.getPrivate().getEncoded()), Arrays.toString(pair.getPublic().getEncoded())};
        Client.main(keys);
    }
}
