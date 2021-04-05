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
import java.security.SecureRandom;
import java.security.PrivateKey;
import java.security.KeyPair;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;


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
            String saltEnc = clientIn.nextLine();
            String ivEnc = clientIn.nextLine();
            
            byte[] ivByteCode =  Base64.getDecoder().decode(ivEnc);
            byte[] sesh_KeyByteCode = Base64.getDecoder().decode(sesh_Key);
            byte[] enc_saltByteCode = Base64.getDecoder().decode(saltEnc);
            String sesh_KeyByteDecode = new String(rCipher.doFinal(sesh_KeyByteCode));
            String saltString = new String(rCipher.doFinal(enc_saltByteCode));
            String ivString = new String(rCipher.doFinal(ivByteCode));
            
            IvParameterSpec ivParameterSpec = new IvParameterSpec(new byte[16]);
            
            System.out.println("Session Key: " + sesh_KeyByteDecode);        
            System.out.println("Salt: " + saltString); 
            System.out.println("iv: "+ ivParameterSpec);
            
            String enc_cardHolderName = clientIn.nextLine();
            System.out.println("Encrypted Cardholder Name: " + enc_cardHolderName);
            
            String enc_cardNumber = clientIn.nextLine();
            System.out.println("Encrypted Credit Card Number: " + enc_cardNumber);
            
            String enc_cardExp = clientIn.nextLine();
            System.out.println("Encrypted Credit Card Expiry: " + enc_cardExp);
            
            String enc_cardCVV = clientIn.nextLine();
            System.out.println("Encrypted Credit Card CVV Code: " + enc_cardCVV);

            SecretKey SecKey_gen = getKeyFromPassword(sesh_KeyByteDecode,saltString);

            String dec_Name = decrypt(enc_cardHolderName, SecKey_gen,ivParameterSpec);
            String dec_Number = decrypt(enc_cardNumber, SecKey_gen,ivParameterSpec);
            String dec_Exp = decrypt(enc_cardExp, SecKey_gen,ivParameterSpec);
            String dec_CVV = decrypt(enc_cardCVV, SecKey_gen,ivParameterSpec);
            
            System.out.println("Decrypted Cardholder Name: " + dec_Name);
            System.out.println("Decrypted Credit Card Number: " + dec_Number);
            System.out.println("Decrypted Expiry Date in MMYY: " + dec_Exp);
            System.out.println("Decrypted Credit Card CVV Code: " + dec_CVV);
            
        }
     catch (IOException i) {
        System.out.println(i);
    } catch (NoSuchAlgorithmException e) {
		e.printStackTrace();
	} catch (IllegalBlockSizeException e) {
		e.printStackTrace();
	} catch (BadPaddingException e) {
		e.printStackTrace();
	} catch (InvalidKeyException e) {
		e.printStackTrace();
	} catch (NoSuchPaddingException e) {
		e.printStackTrace();
	} catch (InvalidKeySpecException e) {
		e.printStackTrace();
	} catch (InvalidAlgorithmParameterException e) {
		e.printStackTrace();
	}        
    }

	public static SecretKey getKeyFromPassword(String password, String salt)
		    throws NoSuchAlgorithmException, InvalidKeySpecException {
		    
		    SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		    KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 256);
		    SecretKey secret = new SecretKeySpec(factory.generateSecret(spec)
		        .getEncoded(), "AES");
		    return secret;
	}
	
	public static IvParameterSpec generateIv() {
	    byte[] iv = new byte[16];
	    new SecureRandom().nextBytes(iv);
	    return new IvParameterSpec(iv);
	}
	
	public static String decrypt(String encryptedMessage, SecretKey SecKey_gen, IvParameterSpec iv) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		String en_Msg = encryptedMessage;
		
		Cipher DES_Cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    	DES_Cipher.init(Cipher.DECRYPT_MODE, SecKey_gen, iv);         
    	
    	byte[] decByteCode = Base64.getDecoder().decode(en_Msg);            
    	byte[] deEncByte = DES_Cipher.doFinal(decByteCode);
    	
    	String dec_FinalMsg = new String(deEncByte);
    	
		return dec_FinalMsg;
	}
		
}


