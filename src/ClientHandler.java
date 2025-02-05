import java.io.EOFException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class ClientHandler implements Runnable {
    private Socket socket;
    private ObjectOutputStream out;
    private ObjectInputStream in;
    private SecretKey sharedKey;

    public ClientHandler(Socket socket) {
        this.socket = socket;
    }

    @Override
    public void run() {
        try {
            out = new ObjectOutputStream(socket.getOutputStream());
            in = new ObjectInputStream(socket.getInputStream());

            // Generate RSA key pair
            KeyPair keyPair = RSA_Asimetric.randomGenerate(1024);
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            // Create certificate using keytool
            createCertificate(publicKey);

            // Send certificate to client
            byte[] certificateBytes = Files.readAllBytes(Paths.get("serverCert.crt"));
            out.writeObject(certificateBytes);

            // Receive encrypted symmetric key from client
            Packet receivedPacket = (Packet) in.readObject();
            byte[] decryptedSymmetricKey = RSA_Asimetric.decryptData(receivedPacket.message, privateKey);

            System.out.println("Symmetric key: " + new String(decryptedSymmetricKey));


            // Verify integrity of the symmetric key
            byte[] calculatedHash = Hash.passwordKeyGeneration(new String(decryptedSymmetricKey), 128).getEncoded();

            System.out.println("Calculated hash: " + new String(calculatedHash));

            if (!Hash.compareHash(new SecretKeySpec(calculatedHash, "AES"), new SecretKeySpec(receivedPacket.hash, "AES"))) {
                System.err.println("Error: Symmetric key integrity check failed.");
                return;
            }

            sharedKey = new SecretKeySpec(decryptedSymmetricKey, "AES");

            // Listen for messages from the client
            while (true) {
                Packet dataPacket = (Packet) in.readObject();
                byte[] decryptedData = AES_Simetric.decryptData(sharedKey, dataPacket.message);
                String message = new String(decryptedData);

                // Verify integrity of the message
                byte[] calculatedMessageHash = Hash.passwordKeyGeneration(message, 128).getEncoded();
                if (!Hash.compareHash(new SecretKeySpec(calculatedMessageHash, "AES"), new SecretKeySpec(dataPacket.hash, "AES"))) {
                    System.err.println("Error: Message integrity check failed.");
                    continue;
                }

                // Broadcast message to all clients
                broadcastMessage(message);

                // Send acknowledgment
                String acknowledgmentMessage = "Message received.";
                byte[] acknowledgmentHash = Hash.passwordKeyGeneration(acknowledgmentMessage, 128).getEncoded();
                byte[] acknowledgment = AES_Simetric.encryptData(sharedKey, acknowledgmentMessage.getBytes());
                out.writeObject(new Packet(acknowledgment, acknowledgmentHash));
            }
        } catch (EOFException e) {
            System.out.println("Client disconnected.");
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try { socket.close(); } catch (IOException e) { e.printStackTrace(); }
        }
    }

    private void broadcastMessage(String message) {
        for (ClientHandler client : Server.clients.values()) {
            if (client != this) {
                try {
                    byte[] encryptedMessage = AES_Simetric.encryptData(client.sharedKey, message.getBytes());
                    byte[] hash = Hash.passwordKeyGeneration(message, 128).getEncoded();
                    client.out.writeObject(new Packet(encryptedMessage, hash));
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
    }

    private void createCertificate(PublicKey publicKey) {
        try {
            String command = "keytool -genkeypair -alias serverCert -keyalg RSA -keysize 2048 -validity 365 -keystore server.keystore -storepass password -keypass password -dname \"CN=Server, OU=IT, O=Company, L=City, S=State, C=Country\" -ext san=dns:localhost";
            Process process = Runtime.getRuntime().exec(command);
            process.waitFor();

            command = "keytool -exportcert -alias serverCert -keystore server.keystore -storepass password -file serverCert.crt";
            process = Runtime.getRuntime().exec(command);
            process.waitFor();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}