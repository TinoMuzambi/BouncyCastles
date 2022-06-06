import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

public class Server {

    private final ServerSocket serverSocket;
    KeyPair pair = Hashing.generateKeyPair();
    private final PrivateKey privateKey = pair.getPrivate();
    private final PublicKey publicKey = pair.getPublic();

    public Server(ServerSocket serverSocket) throws GeneralSecurityException {
        this.serverSocket = serverSocket;
    }

    public void startServer() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        System.err.println("SERVER STARTED");

        while (!serverSocket.isClosed()) {
            Socket socket = serverSocket.accept();
            System.out.println("Connection established!");
            ClientHandler clientHandler = new ClientHandler(socket, publicKey, privateKey);

            Thread thread = new Thread(clientHandler);
            thread.start();
        }
    }

//    public void closeServerSocket() {
//        try {
//            if (serverSocket != null) {
//                serverSocket.close();
//            }
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//    }

    public static void main(String[] args) throws IOException, GeneralSecurityException {
        Hashing.installProvider();
        ServerSocket serverSocket = new ServerSocket(1235);
        Server server = new Server(serverSocket);
        server.startServer();
    }
}

