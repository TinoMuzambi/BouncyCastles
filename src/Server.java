import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

/**
 * This class represents the server in a client-server network.
 */
public class Server {
    /**
     * The socket the server will run on.
     */
    private final ServerSocket serverSocket;
    KeyPair pair = Hashing.generateKeyPair();
    /**
     * The server's private key.
     */
    private final PrivateKey privateKey = pair.getPrivate();
    /**
     * The server's public key.
     */
    private final PublicKey publicKey = pair.getPublic();

    /**
     * Instantiate a Server object.
     * @param serverSocket The socket which the server will run on.
     * @throws GeneralSecurityException Security exceptions.
     */
    public Server(ServerSocket serverSocket) throws GeneralSecurityException {
        this.serverSocket = serverSocket;
    }

    /**
     * Uses System.err.println to log info.
     * @param descriptor The tag for the log.
     */
    private void logger(String descriptor) {
        System.err.println("Server: " + descriptor);
    }

    /**
     * Starts the server on the instantiated socket.
     * @throws IOException Input output errors.
     * @throws NoSuchAlgorithmException No such algorithm in BCFIPS.
     * @throws InvalidKeySpecException Invalid key specification.
     */
    public void startServer() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        logger("server started");

        while (!serverSocket.isClosed()) {
            Socket socket = serverSocket.accept();
            logger("incoming new connection");
            System.out.println("Connection established!");
            ClientHandler clientHandler = new ClientHandler(socket, publicKey, privateKey);

            Thread thread = new Thread(clientHandler);
            thread.start();
        }
    }

    /**
     * Main method which installs the BouncyCastle provider and runs the server.
     * @param args Command line arguments.
     * @throws IOException Input output exceptions.
     * @throws GeneralSecurityException Security errors.
     */
    public static void main(String[] args) throws IOException, GeneralSecurityException {
        Utils.installProvider();
        ServerSocket serverSocket = new ServerSocket(1235);
        Server server = new Server(serverSocket);
        server.startServer();
    }
}

