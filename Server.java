/* Created by Mick Wiedermann on the 31st of October 2021 - Assignment 3 - SENG2250. 
 * Simulates Server for ephemeral diffie-hellman over RSA key exchange.
 * Main executable for Server object.
*/
import java.net.*;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import java.io.*;
import java.math.BigInteger;
  
public class Server {
    
    private static final BigInteger PUBLICKEY = BigInteger.valueOf(65537); // RSA
    private static BigInteger modulus; // Shared modulus for RSA
    private int port;
    private Socket socket;
    private ServerSocket server;
    private DataOutputStream dataOut;
    private DataInputStream dataIn;
    private int serverId;
    private BigInteger sessionId;
    private int clientId;
    private boolean clientAccepted;
  
    public Server(int port) {       // Constructor taking the port number. 
        this.port = port;
        this.socket = null;
        this.server = null;
        this.dataOut = null;
        this.dataIn = null;
        this.serverId = 267;
        this.clientAccepted = false;
    }

    public void start() throws NoSuchAlgorithmException {
        RSA rsa = new RSA(PUBLICKEY); // Creates RSA Tools instance & makes RSA Public Key Available to Client. 
        DH dh = new DH();   // Initiates Diffie-Hellman protocol generting secret exponent and public key. 
        AES aes = new AES(); // Initialises AES Tool kit.
        BigInteger digitalSig = BigInteger.ZERO; // Stores the digital sig for printing purposes. 
        String line = "";

        try { 
            // starts server and waits for a connection.
            server = new ServerSocket(port);
            System.out.println("\nServer started: Waiting for a client ...");
            socket = server.accept();
            dataIn = new DataInputStream(new BufferedInputStream(socket.getInputStream())); // Takes input from the client socket.
            dataOut = new DataOutputStream(socket.getOutputStream());   // Sends output to the socket.
            
            // Receives Client Hello (Client ID).
            this.clientId = dataIn.readInt(); // Sets client ID from initial Hello.
            System.out.println("\t->->-> CLIENT HELLO Received.\n"); 
            
            // Server Replys with n, DH public Key, and digital Signature.  
            System.out.println("SETUP: Sending RSA Public Key + Digital Signature ->->->\n");
            dataOut.writeUTF(rsa.getN().toString()); // Sending Modulus n client message authentication.
            digitalSig = rsa.rsaSign(rsa.getN()); 
            dataOut.writeUTF(digitalSig.toString()); // Sending Digital Signature. 
            
            line = dataIn.readUTF(); // Receives Clients Authentication Response. 
            if (line.equals("VERIFIED")) {
                clientAccepted = true;
            }
            // Receives Client DH Public Key, generates shared secret DH Key. 
            if (!line.equals("End")) {
                BigInteger clientPubKeyDH = new BigInteger(dataIn.readUTF());
                System.out.println("\t->->-> CLIENT DH PubKey and ID:" + clientId + "  Received.\n\tGenerating Shared DH Secret Key.");
                dh.setSharedPrivKey(clientPubKeyDH);
                aes.setSessionKey(dh.getSharedPrivKey());
                generateSessionId();
                System.out.println("\tSecret Shared Diffie-Hellman Key Established.\n");
                System.out.println("SETUP: Sending Session ID and DH Public Key ->->->\n" 
                + "Session ID: " + this.sessionId);
                dataOut.writeUTF(dh.getPubKey().toString()); // Sending DH Public Key. 
                dataOut.writeUTF(this.sessionId.toString());// Sending Session ID.
                String status = dataIn.readUTF();
                System.out.println("\t\n->->-> CLIENT symmetric key generation status: " + status);
                System.out.println("\nSETUP: Handshake Complete - Ephemeral Diffie-Hellman Key Exchange Complete.\n");
                dh.printSecureChanelEstablished();
                aes.setAuthenticationKey(dh.getSharedPrivKey());
            }
            
            
            while (!line.equalsIgnoreCase("End")) {      // reads messages from client until "End" is sent
                try {
                    line = dataIn.readUTF(); 
                    String cipher = dataIn.readUTF();
                    System.out.println("Cipher Received: " + cipher);
                    System.out.println("Message Decrypted: " + line + "\n");
                }
                catch(IOException e) {
                    System.out.println(e + " Inner Catch I/O Exception");
                }
            }
            System.out.println("Closing connection... Goodbye.\n");
            socket.close();     // Closing the connection.
            dataIn.close();     
        } catch(IOException e) {
            System.out.println(e + " Outer Catch I/O Exception");
        }
        if (line.equalsIgnoreCase("End") && clientAccepted) {
            starBand(); // Series of print statement for verifying values - desplayed once end is entered. 
            System.out.println(" ~~ VALUE OF RSA COMPONENTS ~~\n");
            System.out.println("Value of P: \n" + rsa.getP() + "\n");
            System.out.println("Value of Q: \n" + rsa.getQ() + "\n");
            System.out.println("Value of N: \n" + rsa.getN() + "\n");
            System.out.println("Value of M: \n" + rsa.getM() + "\n");
            System.out.println("Value of D: \n" + rsa.getD() + "\n");
            System.out.println("Value of E: \n" + rsa.getE() + "\n");
            System.out.println("Value of GCD: \n" + rsa.testGCD() + "\n");
            System.out.println("Value of e.d-1/m: \n" + rsa.anotherModInverseTest() + "\n");
            System.out.println("Digital Signature: \n" + digitalSig + "\n");
            starBand();
            System.out.println(" ~~ VALUE OF DH COMPONENTS ~~\n");
            System.out.println("Value of Private Exponent: \n" + dh.getSecretExponent() + "\n");
            System.out.println("Value of Public Key: \n" + dh.getPubKey() + "\n");
            System.out.println("Value of Shared Key: \n" + dh.getSharedPrivKey() + "\n");
        }
        
    }

    public static BigInteger getPubKey() {
        return PUBLICKEY;
    } 

    public static BigInteger getModulus() {
        return modulus;
    }

    public void generateSessionId() {
        Random sId = new Random();
        this.sessionId = new BigInteger(256, sId);
    }

    public BigInteger nonce() {
        int nonce = this.clientId*this.serverId;
        return BigInteger.valueOf(nonce);
    }
    public static void starBand() {
        System.out.println("***********************************************************************************");
    }
  
    public static void main(String args[]) throws NoSuchAlgorithmException {
        starBand();
        Server server = new Server(5000);
        server.start();
        starBand();
    }
}