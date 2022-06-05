import java.util.Arrays;

/**
 * A class for wrapping a signed one time key with a signed message digest.
 */
public class KeyWithMessageDigest {

    private final byte[] oneTimeKey;
    private final byte[][][] messageDigest;

    public KeyWithMessageDigest(byte[] oneTimeKey, byte[][][] messageDigest) {
        this.oneTimeKey = oneTimeKey;
        this.messageDigest = messageDigest;
    }

//    public KeyWithMessageDigest(String keyWithMessageDigest) {
//        String oneTimeKeyFromString = keyWithMessageDigest.substring(keyWithMessageDigest.indexOf("oneTimeKey=") + 11, keyWithMessageDigest.indexOf(", messageDigest="));
//        this.oneTimeKey = oneTimeKeyFromString.getBytes();
//
//        String messageDigestFromString = keyWithMessageDigest.substring(keyWithMessageDigest.indexOf(", messageDigest=") + 16);
//        messageDigestFromString = messageDigestFromString.substring(0, messageDigestFromString.length() - 1);
//        this.messageDigest = messageDigestFromString;
//    }

    public byte[] getOneTimeKey() {
        return oneTimeKey;
    }

    public byte[][][] getMessageDigest() {
        return messageDigest;
    }

    @Override
    public String toString() {
        return "KeyWithMessageDigest{" +
                "oneTimeKey=" + Arrays.toString(oneTimeKey) +
                ", messageDigest=" + Arrays.toString(messageDigest) +
                '}';
    }
}
