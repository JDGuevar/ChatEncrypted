import java.io.*;
import java.net.*;
import java.security.PublicKey;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Client {
    private static final String HOST = "localhost";
    private static final int PORT = 5000;

    public static void main(String[] args) {
        try (Socket socket = new Socket(HOST, PORT);
             ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
             BufferedReader reader = new BufferedReader(new InputStreamReader(System.in))) {

            // Rep la clau pública del servidor
            PublicKey serverPublicKey = (PublicKey) in.readObject();

            // Genera una clau simètrica
            SecretKey symmetricKey = AES_Simetric.keygenKeyGeneration(128);
            byte[] symmetricKeyBytes = symmetricKey.getEncoded();

            // Genera hash de la clau simètrica
            byte[] symmetricKeyHash = Hash.passwordKeyGeneration(new String(symmetricKeyBytes), 128).getEncoded();

            // Xifra la clau simètrica amb la clau pública del servidor
            byte[] encryptedSymmetricKey = RSA_Asimetric.encryptData(symmetricKeyBytes, serverPublicKey);

            // Envia la clau simètrica xifrada
            out.writeObject(new Packet(encryptedSymmetricKey, symmetricKeyHash));

            System.out.println("Clau simètrica enviada.");

            // Envia missatges al servidor
            while (true) {
                System.out.print("Introdueix un missatge: ");
                String message = reader.readLine();

                // Genera hash del missatge
                byte[] messageHash = Hash.passwordKeyGeneration(message, 128).getEncoded();

                // Xifra el missatge amb la clau simètrica
                byte[] encryptedMessage = AES_Simetric.encryptData(symmetricKey, message.getBytes());

                // Envia el missatge xifrat
                out.writeObject(new Packet(encryptedMessage, messageHash));

                // Rep acus de rebut
                Packet acknowledgmentPacket = (Packet) in.readObject();
                byte[] decryptedAck = AES_Simetric.decryptData(symmetricKey, acknowledgmentPacket.message);
                String acknowledgment = new String(decryptedAck);

                // Verifica integritat de l'acus de rebut
                byte[] ackHash = Hash.passwordKeyGeneration(acknowledgment, 128).getEncoded();
                if (!Hash.compareHash(new SecretKeySpec(ackHash, "AES"), new SecretKeySpec(acknowledgmentPacket.hash, "AES"))) {
                    System.err.println("Error: L'acus de rebut ha fallat la verificació d'integritat.");
                    continue;
                }

                System.out.println("Resposta del servidor: " + acknowledgment);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}