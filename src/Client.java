import org.bouncycastle.util.Strings;

import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.util.Arrays;
import java.util.Scanner;

public class Client {

    private Socket socket;
    private BufferedReader bufferedReader;
    private BufferedWriter bufferedWriter;
    private String name;
    private String message;

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public Client(Socket socket, String name, String message) throws GeneralSecurityException {

        try {
            this.socket = socket;
            this.bufferedWriter = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
            this.bufferedReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            this.name = name;
            this.message = message;
            KeyPair pair = Hashing.generateKeyPair();
            this.privateKey = pair.getPrivate();
            this.publicKey = pair.getPublic();
        } catch (IOException e) {
            closeEverything(socket, bufferedReader, bufferedWriter);
        }
    }

    public void sendMessage() {
        try {
            bufferedWriter.write(name + " - " + Arrays.toString(publicKey.getEncoded()));

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
                byte[][] signedMessageEncrypted = Encryption.cbcEncrypt(oneTimeKey, signedMessage);
                byte[][] messageToSendBytesEncrypted = Encryption.cbcEncrypt(oneTimeKey, messageToSendBytes);

                // 5. Combine signed message with the original message.
                byte[][][] signedMessageDigest = {signedMessageEncrypted, messageToSendBytesEncrypted};

                // TODO: Server needs to be able to send its public key to clients.
                // 8. Encrypt the one-time key with server's public key.
                byte[] signedOneTimeKey = HashingAndEncryption.kemKeyWrap(serverKeys.getPublic(), oneTimeKey);

                // 9. Combine signed one time key with signed message digest.
                KeyWithMessageDigest keyWithMessageDigest = new KeyWithMessageDigest(signedOneTimeKey, signedMessageDigest);

                // 9. Send to server.
                bufferedWriter.write(name + ": " + keyWithMessageDigest);

                bufferedWriter.newLine();
                bufferedWriter.flush();
            }
        } catch (IOException | GeneralSecurityException e) {
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
                        System.out.println(msgFromGroupChat);
                    } catch (IOException e) {
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

            System.out.println("Enter your message");
            String message = scanner.nextLine();

            Socket socket = new Socket("localhost", 1235);

            Client client = new Client(socket, name, message);

//            String encryptedMessage = client.encrypt(message);
//            String decryptedMessage = client.decrypt(encryptedMessage);

//            System.err.println("Encrypted:\n" + encryptedMessage);
//            System.err.println("Decrypted:\n" + decryptedMessage);
            System.err.println(message);

            client.listenForMessage();
            client.sendMessage();

        } catch (Exception ignored) {
        }

    }

}
