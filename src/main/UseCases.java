package main;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
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

import org.junit.jupiter.api.Test;

import com.upokecenter.cbor.CBORObject;

import COSE.Attribute;
import COSE.CoseException;
import COSE.Encrypt0Message;
import COSE.HeaderKeys;

	public class UseCases {
	
	/**
	 * Convert String (UTF8) into byte[]
	 */
	public static byte[] getByte(String plainText) {
		return plainText.getBytes(StandardCharsets.UTF_8);
	}

	/**
	 * Generate Secrete Key needed for crypto use cases
	 */
	public static SecretKey makeKey() throws NoSuchAlgorithmException {
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(256);
		SecretKey key = keyGen.generateKey();
		return key;
	}

	/**
	 * Generate Nonce with secure Random numer generator
	 */
	public static byte[] generateNonce(int nonceLength) {
		try {
		// GENERATE random nonce (number used once)
		final byte[] nonce = new byte[nonceLength];
		SecureRandom random;
		random = SecureRandom.getInstanceStrong();
		random.nextBytes(nonce);
		return nonce;	
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
		
	}

	/**
	 * Implements basic functionality of symmetric encryption
	 */
	public String symmetricEncrypt(SecretKey key, byte[] plainText, byte[] nonce) {
		try {

			// ENCRYPTION
			Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
			GCMParameterSpec spec = new GCMParameterSpec(16 * 8, nonce);
			cipher.init(Cipher.ENCRYPT_MODE, key, spec);

			byte[] byteCipher = cipher.doFinal(plainText);
			// CONVERSION of raw bytes to BASE64 representation
			String cipherText = Base64.getEncoder().encodeToString(byteCipher);
			return cipherText;

		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
				| InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Implements basic functionality of symmetric decryption
	 */
	public String symmetricDecrypt(SecretKey key, String cipherText, byte[] nonce) {
		try {
			Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
			GCMParameterSpec spec = new GCMParameterSpec(16 * 8, nonce);
			cipher.init(Cipher.DECRYPT_MODE, key, spec);
			byte[] decryptedCipher = cipher.doFinal(Base64.getDecoder().decode(cipherText));
			String decryptedCipherText = new String(decryptedCipher, StandardCharsets.UTF_8);
			return decryptedCipherText;
		} catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException
				| InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchPaddingException e) {
			e.printStackTrace();
			return null;
		}
	}

	public String hash(String plainText) {
		try {
			// Get MessageDigest Instance
			MessageDigest messageDigest = MessageDigest.getInstance("SHA-512");

			// CREATE HASH
			byte[] hashBytes = messageDigest.digest(plainText.getBytes(StandardCharsets.UTF_8));

			// CONVERT/ENCODE IN BASE64
			String hashString = Base64.getEncoder().encodeToString(hashBytes);
			return hashString;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
		
	}
	
	//Some experiments with COSE
			public void createMessage() {
				String nonce = "NONCE";
				String algo ="AES";
				Encrypt0Message o = new Encrypt0Message();
				o.SetContent("Confidential");
				CBORObject ob = CBORObject.FromObject(32);
				CBORObject n = CBORObject.FromObject(nonce);
				try {
					o.addAttribute(n, ob, Attribute.PROTECTED);
					o.addAttribute(HeaderKeys.Algorithm, CBORObject.FromObject(algo), Attribute.PROTECTED);
				} catch (CoseException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
				//CBORObject algX = findA;
				System.out.println(o.findAttribute(HeaderKeys.Algorithm));
				System.out.println(o.getProtectedAttributes());
				System.out.println(o.findAttribute(n));
				assertEquals(1, 1);
			}
	
 
}
