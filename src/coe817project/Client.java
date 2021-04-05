package coe817project;

import java.beans.Encoder;
import java.io.IOException;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.net.Socket;
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
import java.util.Base64;
import java.util.Date;
import java.util.Scanner;
import java.text.SimpleDateFormat;

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


public class Client {
	
	public static void main(String[] args) throws IOException {
        
		Cipher c_rCipher;
		PublicKey publicK_A, publicK_B;
        PrivateKey privateK_A;
        KeyPair keyPair_A;
		KeyPairGenerator keyPairGen_A;
        int Socket_Port = 10001;                     
        String IDa = "Initiator A";
        String sessionKey;
        
        System.out.println("====================");
        System.out.println("| Payment Terminal |");
        System.out.println("====================");
        
        Socket ss = new Socket("localhost", Socket_Port);        
        Scanner serverInput = new Scanner(ss.getInputStream());
        Scanner userInput = new Scanner(System.in);      
        System.out.println("Successfully Connected to Seller's Terminal");
        PrintStream printStr = new PrintStream(ss.getOutputStream());        
        
        try{
            keyPairGen_A = KeyPairGenerator.getInstance("RSA");
            keyPair_A = keyPairGen_A.generateKeyPair();
            publicK_A = keyPair_A.getPublic();
            privateK_A = keyPair_A.getPrivate();            
            String publicKeyString_B = serverInput.nextLine();
            byte [] key_ByteCodeB = Base64.getDecoder().decode(publicKeyString_B);
            X509EncodedKeySpec X509KeySpec = new X509EncodedKeySpec(key_ByteCodeB);
            publicK_B = KeyFactory.getInstance("RSA").generatePublic(X509KeySpec);            
            c_rCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            c_rCipher.init(Cipher.ENCRYPT_MODE,publicK_B);
                                
            SimpleDateFormat dateFormat2 = new SimpleDateFormat("dd-MM-yyyy HH:mm:ss");
            String A_Date = dateFormat2.format(new Date());            
            byte[] c_iDAByteCode = c_rCipher.doFinal(IDa.getBytes("UTF-8"));
            byte[] c_NAByteCode = c_rCipher.doFinal(A_Date.getBytes("UTF-8"));        
            
            String enc_IDa = Base64.getEncoder().encodeToString(c_iDAByteCode);
            String enc_nA = Base64.getEncoder().encodeToString(c_NAByteCode);            
            printStr.println(enc_IDa);
            printStr.println(enc_nA);
            String public_A = Base64.getEncoder().encodeToString(publicK_A.getEncoded());
            printStr.println(public_A);            
            String A_Nonce = serverInput.nextLine();
            String B_Nonce = serverInput.nextLine();            
            c_rCipher.init(Cipher.DECRYPT_MODE, privateK_A);
            byte[] nA_ByteCode = Base64.getDecoder().decode(A_Nonce);
            byte[] nB_ByteCode = Base64.getDecoder().decode(B_Nonce);
            A_Nonce = new String(c_rCipher.doFinal(nA_ByteCode));
            B_Nonce = new String(c_rCipher.doFinal(nB_ByteCode));
                     
            c_rCipher.init(Cipher.ENCRYPT_MODE, publicK_B);
            nB_ByteCode = c_rCipher.doFinal(B_Nonce.getBytes("UTF-8"));
            String nB_Encrypted = Base64.getEncoder().encodeToString(nB_ByteCode);
            printStr.println(nB_Encrypted);
            
            SecureRandom random = new SecureRandom();
            byte bytes[] = new byte[20];
            random.nextBytes(bytes);
            sessionKey = Base64.getEncoder().encodeToString(bytes);
            
            IvParameterSpec ivParameterSpec = new IvParameterSpec(new byte[16]);
            String iv = ivParameterSpec.toString();
            
            byte[] salt = new byte[10];
            random.nextBytes(salt);
            String saltString = Base64.getEncoder().encodeToString(salt);
            
            char[] charSessionKey = new char[sessionKey.length()];
            System.out.println("Session Key: "+ sessionKey);
            System.out.println("Salt: "+ saltString);
            System.out.println("iv: "+ ivParameterSpec);
            
            byte[] ivByte = c_rCipher.doFinal(iv.getBytes("UTF-8"));
            byte[] SeshKey_ByteCode = c_rCipher.doFinal(sessionKey.getBytes("UTF-8"));
            byte[] saltByteCode = c_rCipher.doFinal(saltString.getBytes("UTF-8"));
            String enc_SKByteCode = Base64.getEncoder().encodeToString(SeshKey_ByteCode);
            String enc_saltByteCode = Base64.getEncoder().encodeToString(saltByteCode);
            String enc_ivByteCode = Base64.getEncoder().encodeToString(ivByte);
            
            printStr.println(enc_SKByteCode);
            printStr.println(enc_saltByteCode);
            printStr.println(enc_ivByteCode);
            
            System.out.println("Please Enter your Credit Card Information Below: \n");
            
            System.out.println("Cardholder Name: ");
            String cardHolderName = userInput.nextLine();            
            
            System.out.println("Credit Card Number: ");            
            String cardNumber = userInput.nextLine();  
            isNumber(cardNumber);
            
            System.out.println("Expiry (MMYY): ");
            String cardExp = userInput.nextLine();            
            isNumber(cardExp);    
            
            System.out.println("3 Digit CVV: ");            
            String cardCVV = userInput.nextLine();     
            isNumber(cardCVV);
            
            SecretKey SecKey_gen2 = getKeyFromPassword(sessionKey, saltString);

            String enc_cardHolderName = encrypt(cardHolderName, SecKey_gen2, ivParameterSpec);
            String enc_cardNumber = encrypt(cardNumber, SecKey_gen2, ivParameterSpec);
            String enc_cardExp = encrypt(cardExp, SecKey_gen2, ivParameterSpec);
            String enc_cardCVV = encrypt(cardCVV, SecKey_gen2, ivParameterSpec);
            System.out.println("encrypted");
            
            printStr.println(enc_cardHolderName); 
            printStr.println(enc_cardNumber);
            printStr.println(enc_cardExp); 
            printStr.println(enc_cardCVV); 
                                    
            System.out.println("Credit Card Information has been Securely Transmitted to Seller");
            
        } catch (IOException i) {
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
	
	public static boolean isNumber(String str) {
		try {
			double v = Double.parseDouble(str);
			if(v>0)return true;
			else return false;
		} catch (NumberFormatException e) {	
			System.out.println("Please enter positive integer values only.");
			return false;
		}
	}
	
	public static IvParameterSpec generateIv() {
	    byte[] iv = new byte[16];
	    new SecureRandom().nextBytes(iv);
	    return new IvParameterSpec(iv);
	}
	
	public static String encrypt(String encryptedMessage, SecretKey SecKey_gen, IvParameterSpec iv) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, InvalidAlgorithmParameterException {
		Cipher DES_Cipher2 = Cipher.getInstance("AES/CBC/PKCS5Padding");
       
		DES_Cipher2.init(Cipher.ENCRYPT_MODE, SecKey_gen, iv);              
        byte[] Msg_ByteCode = DES_Cipher2.doFinal(encryptedMessage.getBytes("UTF-8"));
        
        String enc_Msg = Base64.getEncoder().encodeToString(Msg_ByteCode);
        
		return enc_Msg;
	}
}