import java.util.Arrays;

public class KeyWithMessageDigest {

    private final byte[] oneTimeKey;
    private final byte[][][] messageDigest;

    public KeyWithMessageDigest(byte[] oneTimeKey, byte[][][] messageDigest) {
        this.oneTimeKey = oneTimeKey;
        this.messageDigest = messageDigest;
    }

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
