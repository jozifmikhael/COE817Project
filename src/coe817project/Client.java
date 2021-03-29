package coe817project;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


public class Client {
	Cipher c_rCipher;
	PublicKey publicK_A, publicK_B;
    PrivateKey privateK_A;
    KeyPair keyPair_A;
	KeyPairGenerator keyPairGen_A;
    int Socket_Port = 10001;                     
    String IDa = "Initiator A";
    String sessionKey = "SESSION KEY SUCCESSFUL";
	private Socket socket;
	private BufferedReader input;
    private DataOutputStream out;
    private DataInputStream in;
    
	public Client(String address, int port) throws InvalidKeyException, NoSuchPaddingException {
		try {
            socket = new Socket(address, port);
            System.out.println("Initiator A Connected" +"\n");

            //ready the input reader
            input = new BufferedReader(new InputStreamReader(System.in));
            in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
            out = new DataOutputStream(socket.getOutputStream());

            String messagein = "";
            String messageout = "";
		} catch (IOException i) {
            System.out.println(i);
        } 
//            catch (NoSuchAlgorithmException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		} catch (IllegalBlockSizeException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		} catch (BadPaddingException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
	}
	
	public static void main(String args[]) throws InvalidKeyException, NoSuchPaddingException {
		
        Client buyer = new Client("127.0.0.1", 6666);
    }
}
