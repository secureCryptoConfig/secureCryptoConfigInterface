package main;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;



public class SymmetricEncryption {
	
	public byte[] getByte (String plainText) {
		return plainText.getBytes(StandardCharsets.UTF_8);
	}
	
	public String getString (byte[] b) {
		return new String(b, StandardCharsets.UTF_8);
	}

	public SecretKey makeKey() throws NoSuchAlgorithmException {
		KeyGenerator keyGen;
		keyGen = KeyGenerator.getInstance("AES");
	    keyGen.init(256);
	    SecretKey key = keyGen.generateKey();
	    return key;
		
	}
	
	public byte[] generateNonce(int nonceLength) throws NoSuchAlgorithmException {
		 // GENERATE random nonce (number used once)
	      final byte[] nonce = new byte[32];
	      SecureRandom random = SecureRandom.getInstanceStrong();
	      random.nextBytes(nonce);
	      return nonce;
	}
	
	//Only general symmetric encryption
	public String encrypt(SecretKey key, byte[] plainText, byte[] nonce)
	{
	      try {
	    
	      // ENCRYPTION
	      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
	      GCMParameterSpec spec = new GCMParameterSpec(16 * 8, nonce);
	      cipher.init(Cipher.ENCRYPT_MODE, key, spec);

	      byte[] byteCipher = cipher.doFinal(plainText);
	      // CONVERSION of raw bytes to BASE64 representation
	     String cipherText = Base64.getEncoder().encodeToString(byteCipher);
	     return cipherText;
	      
	      }catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | 
	    		  IllegalBlockSizeException | BadPaddingException e) {
	    	  e.printStackTrace();
	    	  return null;
		} 
	}
	
	public String decrypt(SecretKey key, String cipherText, byte[] nonce) {
		try {
	      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
	      GCMParameterSpec spec = new GCMParameterSpec(16 * 8, nonce);
	      cipher.init(Cipher.DECRYPT_MODE, key, spec);
		  byte[] decryptedCipher = cipher.doFinal(Base64.getDecoder().decode(cipherText));
		  String decryptedCipherText = new String(decryptedCipher, StandardCharsets.UTF_8);
		  return decryptedCipherText;
		} catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchPaddingException e) {
			e.printStackTrace();
			return null;
		}
	}



}
