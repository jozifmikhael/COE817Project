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
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
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


public class Client {
	
	public static void main(String[] args) throws IOException {
        
		Cipher c_rCipher;
		PublicKey publicK_A, publicK_B;
        PrivateKey privateK_A;
        KeyPair keyPair_A;
		KeyPairGenerator keyPairGen_A;
        int Socket_Port = 10001;                     
        String IDa = "Initiator A";
        String sessionKey; //= "ARANDOMEVALUE";
        
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
//            System.out.println("Nonce A: " + A_Nonce);
//            System.out.println("Nonce B: " + B_Nonce);            
                     
            c_rCipher.init(Cipher.ENCRYPT_MODE, publicK_B);
            nB_ByteCode = c_rCipher.doFinal(B_Nonce.getBytes("UTF-8"));
            String nB_Encrypted = Base64.getEncoder().encodeToString(nB_ByteCode);
            printStr.println(nB_Encrypted);
            
            SecureRandom random = new SecureRandom();
            byte bytes[] = new byte[20];
            random.nextBytes(bytes);
            //Encoder encoder = Base64.getEncoder().withoutPadding();
            sessionKey = Base64.getEncoder().encodeToString(bytes);
            System.out.println(sessionKey);
            
            byte[] SeshKey_ByteCode = c_rCipher.doFinal(sessionKey.getBytes("UTF-8"));
            String enc_SKByteCode = Base64.getEncoder().encodeToString(SeshKey_ByteCode);
            printStr.println(enc_SKByteCode);
            
            System.out.println("Please Enter your Credit Card Information Below: \n");
            
            System.out.println("Cardholder Name: ");
            String cardHolderName = userInput.nextLine();            
                        
            System.out.println("Credit Card Number: ");            
            String cardNumber = userInput.nextLine();  
            
            System.out.println("Expiry (MMYY): ");
            String cardExp = userInput.nextLine();            
                        
            System.out.println("3 Digit CVV: ");            
            String cardCVV = userInput.nextLine();  
            
            SecretKeyFactory SecKey_F2 = SecretKeyFactory.getInstance("DES");
            DESKeySpec KeyDES_Bytes2 = new DESKeySpec(sessionKey.getBytes());
            SecretKey SecKey_gen2 = SecKey_F2.generateSecret(KeyDES_Bytes2);
            
            String enc_cardHolderName = encrypt(cardHolderName, SecKey_gen2);
            String enc_cardNumber = encrypt(cardNumber, SecKey_gen2);
            String enc_cardExp = encrypt(cardExp, SecKey_gen2);
            String enc_cardCVV = encrypt(cardCVV, SecKey_gen2);
            
            printStr.println(enc_cardHolderName); 
            printStr.println(enc_cardNumber);
            printStr.println(enc_cardExp); 
            printStr.println(enc_cardCVV); 
                                    
            System.out.println("Credit Card Information has been Securely Transmitted to Seller");
            
        } catch (Exception e){
            System.out.println(e.getMessage());
        }
	}
	
	public static String encrypt(String encryptedMessage, SecretKey SecKey_gen) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
		Cipher DES_Cipher2 = Cipher.getInstance("DES/ECB/PKCS5Padding");
        DES_Cipher2.init(Cipher.ENCRYPT_MODE, SecKey_gen);            
        
        byte[] Msg_ByteCode = DES_Cipher2.doFinal(encryptedMessage.getBytes("UTF-8"));
        
        String enc_Msg = Base64.getEncoder().encodeToString(Msg_ByteCode);
		return enc_Msg;
	}
}