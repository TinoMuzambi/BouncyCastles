import javax.crypto.Cipher;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
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
    private static final String PRIVATE_KEY_STRING = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAJ2qoa4HT8GQcxohvKte2YJMUpANDKQXevxBpFVSWfinX/JGP3ZPzTE2bmcJokByq3nRYGvZe3sqBGaaTfTuECvG/9H0izCbT4ESWyg4h6bXwjkJqZs75XgZP93zby/aD+SeYveCp4nAmLRJSoCStarSAnIyNPkFrq5CBQnQNAdnAgMBAAECgYAFeM8MradIdf1wqjwUjIGrAoAZDMLkDQaRK6wK5AVIWnK7g1Gfhwx9iUCSpeRyLSijXS9l/tHIyAAIGZHcDskT1dpkOgOWqnRrotnoUFPAWojdxJ2CUR8DCve4dC0f/RWFLK1FmPfoqpbe0GcWjnW4l9rZbRft4+YD+ZGGJ86YbQJBALULb/Uqpne5Upz8B0UjYVefrh+ENMgQmNHeK9GHdCsOukbbc8rBXW+cjAOqfT1ncipM3gHA1uNoTOFfbIgHBx0CQQDe8WQljZi1q3GQt4UYhs3+gZ184gubsbzIrKoYuSybMcJD5SCIZr+0I6yL3l8dOSsHGpAWagFmjGbwfSBsnU1TAkEAq5J3O4R71iJO5G8EBMWOzpeJUFzeGGuCKAHAzQTtVpDSf6whhBjUD53wItlDbxnF28iU7FxwSXriwQLJu+/NEQJABRsoPQfyMG79yd+6J6amvyZ+0eZnd6hpd3sk5i4PjHpmRaHQze70gw6yG/361bOCfcYo+Kpy38NldCqZfINZywJARqpKZwDFcksA7h+SqiS6xG+Szo9BiaZ1vQ7B8lcQFQl/bcWlMuxRO7yFrex/0L3zrOgBlX0khk8FCQnA19dDYg==";
    private static final String PUBLIC_KEY_STRING = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCdqqGuB0/BkHMaIbyrXtmCTFKQDQykF3r8QaRVUln4p1/yRj92T80xNm5nCaJAcqt50WBr2Xt7KgRmmk307hArxv/R9Iswm0+BElsoOIem18I5CambO+V4GT/d828v2g/knmL3gqeJwJi0SUqAkrWq0gJyMjT5Ba6uQgUJ0DQHZwIDAQAB";


    public Client(Socket socket, String name, String message){

        try {
            this.socket = socket;
            this.bufferedWriter = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
            this.bufferedReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            this.name = name;



        } catch (IOException e){
            closeEverything(socket, bufferedReader, bufferedWriter);
        }
    }
    public Client(){


    }

    public void init(){
        try{
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(1024);
            KeyPair pair = generator.generateKeyPair();
            privateKey = pair.getPrivate();
            publicKey = pair.getPublic();
        }catch (Exception ignored){
        }
    }

    public void initFromStrings(){
        try{
            X509EncodedKeySpec keySpecPublic = new X509EncodedKeySpec(decode(PUBLIC_KEY_STRING));
            PKCS8EncodedKeySpec keySpecPrivate = new PKCS8EncodedKeySpec(decode(PRIVATE_KEY_STRING));

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
    public static void main(String[] args) throws IOException {


        try {


            Scanner scanner = new Scanner(System.in);

            System.out.println("Enter your name");
            String name = scanner.nextLine();

            System.out.println("Enter your message");
            String message = scanner.nextLine();



            Socket socket = new Socket("localhost", 1235);

            Client client = new Client(socket, name, message);
            client.initFromStrings();

            String encryptedMessage = client.encrypt(message);
            String descruptedMessage = client.decrypt(encryptedMessage);

            System.err.println("Encrypted:\n"+encryptedMessage);
            System.err.println("Decrypted:\n"+descruptedMessage);

            client.listenForMessage();
            client.sendMessage();

        }catch (Exception ingored){}

    }


}
