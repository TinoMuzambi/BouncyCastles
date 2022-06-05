import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

public class Server {
    private final ServerSocket serverSocket;
    private PrivateKey privateKey;
    private PublicKey publicKey;

    public Server(ServerSocket serverSocket) throws GeneralSecurityException {
        this.serverSocket = serverSocket;
        KeyPair pair = Hashing.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();
    }

    public void startServer(){
        try{
            while (!serverSocket.isClosed()) {
                Socket socket = serverSocket.accept();
                System.out.println("Connection established!");
                ClientHandler clientHandler = new ClientHandler(socket);

                Thread thread = new Thread(clientHandler);
                thread.start();
            }
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException ignored){
        }
    }

    public static void main(String[] args) throws IOException, GeneralSecurityException {
       ServerSocket serverSocket = new ServerSocket(1235);
       Server server = new Server(serverSocket);
       server.startServer();
    }
}

