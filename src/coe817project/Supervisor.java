package coe817project;

import java.io.IOException;
import java.io.PrintStream;
import java.text.SimpleDateFormat;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Base64;
import java.util.Date;
import java.util.Scanner;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyPair;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;


public class Supervisor {
	
	public static void main(String[] args) throws IOException {
        
		Cipher rCipher;
		PublicKey publicK_A, publicK_B;
        PrivateKey privateK_B;   
        KeyPair keyPair_B;
        KeyPairGenerator keyPairGen_B;
        int Socket_Port = 10001;
        
        String IDb = "Seller";

        System.out.println("=====================");
        System.out.println("| Seller's Terminal |");
        System.out.println("=====================");        
        ServerSocket ss = new ServerSocket(Socket_Port);        
        System.out.println("Starting connection to Client's terminal on socket: " + Socket_Port);        
        Socket ssc = ss.accept();    
        System.out.println("Successfully Connected to Client");
        Scanner clientIn = new Scanner(ssc.getInputStream());
        PrintStream printStr = new PrintStream(ssc.getOutputStream());
                       
        try {
            
            keyPairGen_B = KeyPairGenerator.getInstance("RSA");
            keyPair_B = keyPairGen_B.generateKeyPair();
            publicK_B = keyPair_B.getPublic();
            privateK_B = keyPair_B.getPrivate();            
            String publicKeyString_B = Base64.getEncoder().encodeToString(publicK_B.getEncoded());
            printStr.println(publicKeyString_B);            
            rCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rCipher.init(Cipher.DECRYPT_MODE, privateK_B);            
            String client_IDa = clientIn.nextLine();
            String client_nA = clientIn.nextLine();
            byte[] c_byteCode = Base64.getDecoder().decode(client_IDa);
            byte[] c_nAByteCode = Base64.getDecoder().decode(client_nA);
            client_IDa = new String(rCipher.doFinal(c_byteCode));
            client_nA = new String(rCipher.doFinal(c_nAByteCode));
            System.out.println("Client's ID is: " + client_IDa + " -- with timestamp: -- " + client_nA );            
            
            String ServerPublicKey_A = clientIn.nextLine();
            byte[] s_nAByteCode = Base64.getDecoder().decode(ServerPublicKey_A);
            X509EncodedKeySpec X509_KeySpec = new X509EncodedKeySpec(s_nAByteCode);
            publicK_A = KeyFactory.getInstance("RSA").generatePublic(X509_KeySpec);            
            SimpleDateFormat dateFormat = new SimpleDateFormat("dd-MM-yyyy HH:mm:ss");
            String B_Date = dateFormat.format(new Date());            
            rCipher.init(Cipher.ENCRYPT_MODE, publicK_A);
            byte[] c_nAByteCode2 = rCipher.doFinal(client_nA.getBytes("UTF-8"));
            byte[] c_nBByteCode2 = rCipher.doFinal(B_Date.getBytes("UTF-8"));
            String enc_nA = Base64.getEncoder().encodeToString(c_nAByteCode2);
            String enc_nB = Base64.getEncoder().encodeToString(c_nBByteCode2);            
            printStr.println(enc_nA);
            printStr.println(enc_nB);
            
            rCipher.init(Cipher.DECRYPT_MODE, privateK_B);
            String c_nB = clientIn.nextLine();
            byte[] c_BDecByteCode = Base64.getDecoder().decode(c_nB);
            c_nB = new String(rCipher.doFinal(c_BDecByteCode));
            System.out.println("Received Timestamp: " + c_nB);            
            String sesh_Key = clientIn.nextLine();
            byte[] sesh_KeyByteCode = Base64.getDecoder().decode(sesh_Key);
            String sesh_KeyByteDecode = new String(rCipher.doFinal(sesh_KeyByteCode));
            System.out.println("Session Key: " + sesh_KeyByteDecode);            
            
            String enc_cardHolderName = clientIn.nextLine();
            System.out.println("Encrypted Cardholder Name: " + enc_cardHolderName);
            
            String enc_cardNumber = clientIn.nextLine();
            System.out.println("Encrypted Credit Card Number: " + enc_cardNumber);
            
            String enc_cardExp = clientIn.nextLine();
            System.out.println("Encrypted Credit Card Expiry: " + enc_cardExp);
            
            String enc_cardCVV = clientIn.nextLine();
            System.out.println("Encrypted Credit Card CVV Code: " + enc_cardCVV);
            
            SecretKeyFactory SecKey_F = SecretKeyFactory.getInstance("DES");
            DESKeySpec KeyDES_Bytes = new DESKeySpec(sesh_KeyByteDecode.getBytes());
            SecretKey SecKey_gen = SecKey_F.generateSecret(KeyDES_Bytes);
            
            String dec_Name = decrypt(enc_cardHolderName, SecKey_gen);
            String dec_Number = decrypt(enc_cardNumber, SecKey_gen);
            String dec_Exp = decrypt(enc_cardExp, SecKey_gen);
            String dec_CVV = decrypt(enc_cardCVV, SecKey_gen);
            
            System.out.println("Decrypted Cardholder Name: " + dec_Name);
            System.out.println("Decrypted Credit Card Number: " + dec_Number);
            System.out.println("Decrypted Expiry Date in MMYY: " + dec_Exp);
            System.out.println("Decrypted Credit Card CVV Code: " + dec_CVV);
            
            
        }
        catch (Exception e)
        {
            System.out.println(e);
        }        
    }

	public static String decrypt(String encryptedMessage, SecretKey SecKey_gen) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		String en_Msg = encryptedMessage;
		Cipher DES_Cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
    	DES_Cipher.init(Cipher.DECRYPT_MODE, SecKey_gen);            
    	byte[] decByteCode = Base64.getDecoder().decode(en_Msg);            
    	byte[] deEncByte = DES_Cipher.doFinal(decByteCode);
    	String dec_FinalMsg = new String(deEncByte);
		return dec_FinalMsg;
	}
		
}


