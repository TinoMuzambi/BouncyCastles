import org.bouncycastle.util.Strings;

import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

public class Client {

    private Socket socket;
    private BufferedReader bufferedReader;
    private BufferedWriter bufferedWriter;
    private String name;
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private PublicKey serverPublicKey;


    public Client(Socket socket, String name) {
        try {
            this.socket = socket;
            this.bufferedWriter = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
            this.bufferedReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            this.name = name;
        } catch (IOException e) {
//            closeEverything(socket, bufferedReader, bufferedWriter);
        }
    }

    public void initFromStrings(String privateKeyBytes, String publicKeyBytes) {
        try {
            X509EncodedKeySpec keySpecPublic = new X509EncodedKeySpec(decode(publicKeyBytes));
            PKCS8EncodedKeySpec keySpecPrivate = new PKCS8EncodedKeySpec(decode(privateKeyBytes));

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            publicKey = keyFactory.generatePublic(keySpecPublic);
            logger("public key", encode(publicKey.getEncoded()));
            privateKey = keyFactory.generatePrivate(keySpecPrivate);
            logger("private key", encode(privateKey.getEncoded()));
        } catch (Exception ignored) {
        }
    }

    private String encode(byte[] data){ return Base64.getEncoder().encodeToString(data); }

    private byte[] decode(String data) {
        return Base64.getDecoder().decode(data);
    }

    private void logger(String descriptor, String data) {
        System.err.println("Client [" + name + "]: " + descriptor + " - " + data);
    }

    public void sendMessage() throws GeneralSecurityException {
        try {
            String UKString = name + " - " + Base64.getEncoder().encodeToString(publicKey.getEncoded());
            logger("public key being sent to server", UKString);
            bufferedWriter.write(UKString);
            bufferedWriter.newLine();
            bufferedWriter.flush();

            Scanner scanner = new Scanner(System.in);
            while (socket.isConnected()) {
                String messageToSend = scanner.nextLine();
                logger("message to send", messageToSend);

                byte[] messageToSendBytes = Strings.toByteArray(messageToSend);
                logger("message to send bytes", encode(messageToSendBytes));

                // 3. Compress message.
                byte[] messageToSendBytesCompressed = Hashing.compressData(messageToSendBytes);
                logger("message to send bytes compressed", encode(messageToSendBytesCompressed));

                // 3. Hash compressed message.
                byte[] messageToSendBytesCompressedHashed = Hashing.calculateSha3Digest(messageToSendBytesCompressed);
                logger("message to send bytes compressed hashed", encode(messageToSendBytesCompressedHashed));

                // 4. Sign message with private key.
                byte[] signedMessage = Hashing.generatePkcs1Signature(privateKey, messageToSendBytesCompressedHashed);
                logger("signed message", encode(signedMessage));

                // 6. Initialise and generate one-time secret key.
                Encryption.defineKey(new byte[128 / 8]);
                Encryption.defineKey(new byte[192 / 8]);
                Encryption.defineKey(new byte[256 / 8]);
                SecretKey oneTimeKey = Encryption.generateKey();
                logger("one-time secret key", encode(oneTimeKey.getEncoded()));

                // 7. Encrypt messages with one time key.
                byte[][] signedMessageEncryptedRes = Encryption.cbcEncrypt(oneTimeKey, signedMessage);
                byte[] signedMessageEncryptedIV = signedMessageEncryptedRes[0];
                logger("signed message initialisation vector", encode(signedMessageEncryptedIV));
                byte[] signedMessageEncrypted = signedMessageEncryptedRes[1];
                logger("signed message encrypted", encode(signedMessageEncrypted));
                byte[][] messageToSendBytesEncryptedRes = Encryption.cbcEncrypt(oneTimeKey, messageToSendBytes);
                byte[] messageToSendBytesEncryptedIV = messageToSendBytesEncryptedRes[0];
                logger("original message initialisation vector", encode(messageToSendBytesEncryptedIV));
                byte[] messageToSendBytesEncrypted = messageToSendBytesEncryptedRes[1];
                logger("original message encrypted", encode(messageToSendBytesEncrypted));

                // 8. Encrypt the one-time key with server's public key.
                byte[] signedOneTimeKey = HashingAndEncryption.kemKeyWrap(serverPublicKey, oneTimeKey);
                logger("one time key wrapped with server's public key", encode(signedOneTimeKey));

                // 5./9. Combine signed one time key with signed message digest and send to server.
                logger("message being sent to server", name + ": " + encode(signedOneTimeKey) + " - " + encode(signedMessageEncryptedIV) + " - " + encode(signedMessageEncrypted) + " - " + encode(messageToSendBytesEncryptedIV) + " - " + encode(messageToSendBytesEncrypted));
                bufferedWriter.write(name + ": " + encode(signedOneTimeKey) + " - " + encode(signedMessageEncryptedIV) + " - " + encode(signedMessageEncrypted) + " - " + encode(messageToSendBytesEncryptedIV) + " - " + encode(messageToSendBytesEncrypted));
                bufferedWriter.newLine();
                bufferedWriter.flush();
            }
        } catch (IOException e) {
//            closeEverything(socket, bufferedReader, bufferedWriter);
        }
    }

    public void listenForMessage() {
        new Thread(new Runnable() {
            @Override
            public void run() {
                String msgFromGroupChat;

                while (socket.isConnected()) {
                    try {
                        msgFromGroupChat = bufferedReader.readLine();
                        logger("message from group chat", msgFromGroupChat);

                        if (msgFromGroupChat.contains("SERVER: ")) {
                            System.out.println(msgFromGroupChat);
                        } else if (!msgFromGroupChat.contains("UK:SVR")) {
                            // 13. Decrypt signed one time key with receiver's private key.
                            String[] rawData = msgFromGroupChat.split(": ");
                            logger("raw data", Arrays.toString(rawData));
                            String[] data = rawData[1].split(" - ");
                            logger("data", Arrays.toString(data));
                            SecretKey oneTimeKey = (SecretKey) HashingAndEncryption.kemKeyUnwrap(privateKey, decode(data[0]));
                            logger("unwrapped one time secret key", encode(oneTimeKey.getEncoded()));

                            // 14. Decrypt messages with decrypted one time key.
                            byte[] signedMessageEncryptedIV = decode(data[1]);
                            logger("signed message initialisation vector", encode(signedMessageEncryptedIV));
                            byte[] signedMessageEncrypted = decode(data[2]);
                            logger("signed message encrypted", encode(signedMessageEncrypted));
                            byte[] messageBytesEncryptedIV = decode(data[3]);
                            logger("original message initialisation vector", encode(messageBytesEncryptedIV));
                            byte[] messageBytesEncrypted = decode(data[4]);
                            logger("original message encrypted", encode(messageBytesEncrypted));

                            byte[] signedMessageDecrypted = Encryption.cbcDecrypt(oneTimeKey, signedMessageEncryptedIV, signedMessageEncrypted);
                            logger("signed message decrypted with one time key", encode(signedMessageDecrypted));
                            byte[] messageDecrypted = Encryption.cbcDecrypt(oneTimeKey, messageBytesEncryptedIV, messageBytesEncrypted);
                            logger("original message decrypted with one time key", encode(messageDecrypted));

                            // 16. Compress message portion.
                            byte[] messageCompressed = Hashing.compressData(messageDecrypted);
                            logger("original message compressed", encode(messageCompressed));

                            // 16. Hash compressed message.
                            byte[] messageHashed = Hashing.calculateSha3Digest(messageCompressed);
                            logger("original message compressed and hashed", encode(messageHashed));

                            // 15./17. Verify message with public key.
                            boolean messageHashMatch = Hashing.verifyPkcs1Signature(publicKey, messageHashed, signedMessageDecrypted);
                            logger("verification of signatures", String.valueOf(messageHashMatch));
                            if (messageHashMatch) {
                                System.out.println("Verified");
                            }

                            logger("message received from server", rawData[0] + ": " + new String(messageDecrypted, StandardCharsets.UTF_8));
                            System.out.println(rawData[0] + ": " + new String(messageDecrypted, StandardCharsets.UTF_8));
                        } else {
                            X509EncodedKeySpec keySpecPublic = new X509EncodedKeySpec(decode(msgFromGroupChat.substring(8)));
                            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                            serverPublicKey = keyFactory.generatePublic(keySpecPublic);
                            logger("public key received from server", encode(serverPublicKey.getEncoded()));
                        }
                    } catch (IOException | GeneralSecurityException e) {
//                        closeEverything(socket, bufferedReader, bufferedWriter);
                    }
                }
            }
        }).start();
    }

    public void closeEverything(Socket socket, BufferedReader bufferedReader, BufferedWriter bufferedWriter) {
        try {
            if (bufferedReader != null) {
                bufferedReader.close();
            }
            if (bufferedWriter != null) {
                bufferedWriter.close();
            }
            if (socket != null) {
                socket.close();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        try {
            Scanner scanner = new Scanner(System.in);

            System.out.println("Enter your name");
            String name = scanner.nextLine();

            Socket socket = new Socket("localhost", 1235);

            Client client = new Client(socket, name);
            client.initFromStrings(args[0], args[1]);

            client.listenForMessage();
            client.sendMessage();

        } catch (Exception ignored) {
        }
    }
}
