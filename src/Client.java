import org.bouncycastle.util.Strings;

import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
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
            closeEverything(socket, bufferedReader, bufferedWriter);
        }
    }

    public void initFromStrings(String privateKeyBytes, String publicKeyBytes) {
        try {
            X509EncodedKeySpec keySpecPublic = new X509EncodedKeySpec(decode(publicKeyBytes));
            PKCS8EncodedKeySpec keySpecPrivate = new PKCS8EncodedKeySpec(decode(privateKeyBytes));

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            publicKey = keyFactory.generatePublic(keySpecPublic);
            privateKey = keyFactory.generatePrivate(keySpecPrivate);
        } catch (Exception ignored) {
        }
    }

        private String encode(byte[] data){ return Base64.getEncoder().encodeToString(data); }

    private byte[] decode(String data) {
        return Base64.getDecoder().decode(data);
    }

    public void sendMessage() throws GeneralSecurityException {
        try {
            bufferedWriter.write(name + " - " + Base64.getEncoder().encodeToString(publicKey.getEncoded()));
            bufferedWriter.newLine();
            bufferedWriter.flush();

            Scanner scanner = new Scanner(System.in);
            while (socket.isConnected()) {
                String messageToSend = scanner.nextLine();

                byte[] messageToSendBytes = Strings.toByteArray(messageToSend);

                // 3. Compress message.
                byte[] messageToSendBytesCompressed = Hashing.compressData(messageToSendBytes);

                // 3. Hash compressed message.
                byte[] messageToSendBytesCompressedHashed = Hashing.calculateSha3Digest(messageToSendBytesCompressed);

                // 4. Sign message with private key.
                byte[] signedMessage = Hashing.generatePkcs1Signature(privateKey, messageToSendBytesCompressedHashed);

                // 6. Initialise and generate one-time secret key.
                Encryption.defineKey(new byte[128 / 8]);
                Encryption.defineKey(new byte[192 / 8]);
                Encryption.defineKey(new byte[256 / 8]);
                SecretKey oneTimeKey = Encryption.generateKey();

                // 7. Encrypt messages with one time key.
                byte[][] signedMessageEncryptedRes = Encryption.cbcEncrypt(oneTimeKey, signedMessage);
                byte[] signedMessageEncryptedIV = signedMessageEncryptedRes[0];
                byte[] signedMessageEncrypted = signedMessageEncryptedRes[1];
                byte[][] messageToSendBytesEncryptedRes = Encryption.cbcEncrypt(oneTimeKey, messageToSendBytes);
                byte[] messageToSendBytesEncryptedIV = messageToSendBytesEncryptedRes[0];
                byte[] messageToSendBytesEncrypted = messageToSendBytesEncryptedRes[1];

                // 5. Combine signed message with the original message.
//                byte[][][] signedMessageDigest = {signedMessageEncrypted, messageToSendBytesEncrypted};

                // 8. Encrypt the one-time key with server's public key.
                byte[] signedOneTimeKey = HashingAndEncryption.kemKeyWrap(serverPublicKey, oneTimeKey);

                // 9. Combine signed one time key with signed message digest.
//                KeyWithMessageDigest keyWithMessageDigest = new KeyWithMessageDigest(signedOneTimeKey, signedMessageDigest);

                // 5./9. Send to server.
                bufferedWriter.write(name + ": " + encode(signedOneTimeKey) + " - " + encode(signedMessageEncryptedIV) + " - " + encode(signedMessageEncrypted) + " - " + encode(messageToSendBytesEncryptedIV) + " - " + encode(messageToSendBytesEncrypted));

                bufferedWriter.newLine();
                bufferedWriter.flush();
            }
        } catch (IOException e) {
            closeEverything(socket, bufferedReader, bufferedWriter);
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
                        if (!msgFromGroupChat.contains("UK:SERVER")) {
                            System.out.println(msgFromGroupChat);
                        } else {
                            X509EncodedKeySpec keySpecPublic = new X509EncodedKeySpec(decode(msgFromGroupChat.substring(11)));
                            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                            serverPublicKey = keyFactory.generatePublic(keySpecPublic);
                        }
                    } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
                        closeEverything(socket, bufferedReader, bufferedWriter);
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
