import java.io.*;
import java.net.*;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Server {
    private static final int PORT = 5000;

    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("Servidor esperant connexions...");

            try (Socket socket = serverSocket.accept();
                 ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                 ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {

                System.out.println("Client connectat.");

                // Genera claus pública i privada RSA
                KeyPair keyPair = RSA_Asimetric.randomGenerate(2048);
                PublicKey publicKey = keyPair.getPublic();
                PrivateKey privateKey = keyPair.getPrivate();

                // Envia la clau pública al client
                out.writeObject(publicKey);

                // Rep la clau simètrica xifrada del client
                Packet receivedPacket = (Packet) in.readObject();
                byte[] decryptedSymmetricKey = RSA_Asimetric.decryptData(receivedPacket.message, privateKey);

                // Genera hash de la clau simètrica rebuda i verifica integritat
                byte[] calculatedHash = Hash.passwordKeyGeneration(new String(decryptedSymmetricKey), 128).getEncoded();
                if (!Hash.compareHash(new SecretKeySpec(calculatedHash, "AES"), new SecretKeySpec(receivedPacket.hash, "AES"))) {
                    System.err.println("Error: La integritat de la clau simètrica ha fallat.");
                    return;
                }

                // Guarda la clau simètrica
                SecretKey sharedKey = new SecretKeySpec(decryptedSymmetricKey, "AES");
                System.out.println("Clau simètrica rebuda i verificat.");

                // Llegeix missatges xifrats del client
                while (true) {
                    Packet dataPacket = (Packet) in.readObject();

                    // Desxifra el missatge
                    byte[] decryptedData = AES_Simetric.decryptData(sharedKey, dataPacket.message);
                    String message = new String(decryptedData);

                    // Verifica integritat del missatge
                    byte[] calculatedMessageHash = Hash.passwordKeyGeneration(message, 128).getEncoded();
                    if (!Hash.compareHash(new SecretKeySpec(calculatedMessageHash, "AES"), new SecretKeySpec(dataPacket.hash, "AES"))) {
                        System.err.println("Error: La integritat del missatge ha fallat.");
                        continue;
                    }

                    System.out.println("Missatge rebut: " + message);

                    // Envia acus de rebut
                    String acknowledgment = "DataReceived";
                    byte[] ackHash = Hash.passwordKeyGeneration(acknowledgment, 128).getEncoded();
                    byte[] encryptedAck = AES_Simetric.encryptData(sharedKey, acknowledgment.getBytes());
                    out.writeObject(new Packet(encryptedAck, ackHash));
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}