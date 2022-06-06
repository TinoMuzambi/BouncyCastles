import javax.crypto.Cipher;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
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
//            generateKeyPair();
//            this.bufferedWriter.write(name + " - " + Arrays.toString(publicKey.getEncoded()));
        } catch (IOException e){
            closeEverything(socket, bufferedReader, bufferedWriter);
        }
    }

    public void init(PublicKey UK, PrivateKey RK){
            privateKey = RK;
            publicKey = UK;
    }

    public void initFromStrings(byte[] publicKeyString, byte[] privateKeyString){
        try{
            X509EncodedKeySpec keySpecPublic = new X509EncodedKeySpec(publicKeyString);
            PKCS8EncodedKeySpec keySpecPrivate = new PKCS8EncodedKeySpec(privateKeyString);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            publicKey = keyFactory.generatePublic(keySpecPublic);
            privateKey = keyFactory.generatePrivate(keySpecPrivate);


        }catch (Exception ignored){}


    }

    public void setPrivateKey(){
        System.err.println("Public key\n"+ encode(publicKey.getEncoded()));
        System.err.println("Private key\n"+ encode(privateKey.getEncoded()));
    }

    public String encrypt(String message) throws Exception{
        byte[] messageToBytes = message.getBytes();
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE,publicKey);
        byte[] encryptedBytes = cipher.doFinal(messageToBytes);
        return encode(encryptedBytes);
    }

    private String encode(byte[] data){ return Base64.getEncoder().encodeToString(data); }
    public String decrypt(String encryptedMessage) throws Exception{
        byte[] encryptedBytes = decode(encryptedMessage);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedMessage = cipher.doFinal(encryptedBytes);
        return new String(decryptedMessage, "UTF8");

    }
    private byte[] decode(String data){return Base64.getDecoder().decode(data);}

    public void sendMessage(){
        try {
            bufferedWriter.write(name);
            bufferedWriter.newLine();
            bufferedWriter.flush();

            Scanner scanner = new Scanner(System.in);
            while (socket.isConnected()){
                String messageToSend = scanner.nextLine();
                bufferedWriter.write(name + ":" + messageToSend);
                bufferedWriter.newLine();
                bufferedWriter.flush();
            }
        } catch (IOException e){
            closeEverything(socket, bufferedReader, bufferedWriter);
        }
    }

    public void generateKeyPair() {
        new Thread(new Runnable() {
            @Override
            public void run() {
                Hashing.installProvider();
                KeyPairGenerator keyPairGenerator = null;
                try {
                    keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BCFIPS");
                } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
                    throw new RuntimeException(e);
                }
                try {
                    keyPairGenerator.initialize(new RSAKeyGenParameterSpec(3072, RSAKeyGenParameterSpec.F4));
                } catch (InvalidAlgorithmParameterException e) {
                    throw new RuntimeException(e);
                }
                KeyPair pair = keyPairGenerator.generateKeyPair();
                privateKey = pair.getPrivate();
                publicKey = pair.getPublic();
            }
        }).start();
    }

    public void listenForMessage(){
        new Thread(new Runnable() {
            @Override
            public void run() {
                String msgFromGroupChat;

                while (socket.isConnected()){
                    try {
                        msgFromGroupChat = bufferedReader.readLine();
                        System.out.println(msgFromGroupChat);
                    } catch (IOException e){
                        closeEverything(socket, bufferedReader, bufferedWriter);
                    }
                }
            }
        }).start();
    }
    public void closeEverything(Socket socket, BufferedReader bufferedReader, BufferedWriter bufferedWriter) {
        try {
            if (bufferedReader != null){
                bufferedReader.close();
            }
            if (bufferedWriter != null){
                bufferedWriter.close();
            }
            if (socket != null){
                socket.close();
            }
        } catch (IOException e){
            e.printStackTrace();
        }


    }
    public static void main(String[] args) {
        try {
            Scanner scanner = new Scanner(System.in);

            System.out.println(args[0]);
            System.out.println(args[1]);
            System.out.println("Enter your name");
            String name = scanner.nextLine();

            System.out.println("Enter your message");
            String message = scanner.nextLine();

            Socket socket = new Socket("localhost", 1235);

            Client client = new Client(socket, name, message);
            client.initFromStrings(args[0].getBytes(), args[1].getBytes());

            String encryptedMessage = client.encrypt(message);
            String descruptedMessage = client.decrypt(encryptedMessage);

            System.err.println("Encrypted:\n"+encryptedMessage);
            System.err.println("Decrypted:\n"+descruptedMessage);

            client.listenForMessage();
            client.sendMessage();

        } catch (Exception ignored){}
    }

}
