public class KeyWithMessageDigest {

    private final byte[][] oneTimeKey;
    private final byte[][][] messageDigest;

    public KeyWithMessageDigest(byte[][] oneTimeKey, byte[][][] messageDigest) {
        this.oneTimeKey = oneTimeKey;
        this.messageDigest = messageDigest;
    }

    public byte[][] getOneTimeKey() {
        return oneTimeKey;
    }

    public byte[][][] getMessageDigest() {
        return messageDigest;
    }
}
