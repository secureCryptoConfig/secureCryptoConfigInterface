package main;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;

import com.upokecenter.cbor.CBORObject;

import COSE.Attribute;
import COSE.CoseException;
import COSE.Encrypt0Message;
import COSE.HeaderKeys;

public class UseCases {

	public static SCCCiphertext symmetricEncryptWithParams(AbstractSCCKey key, PlaintextContainerInterface plaintext,
			int nonceLength, int tagLength, String algo) {
		try {

			// ENCRYPTION
			Cipher cipher = Cipher.getInstance(algo);

			// GENERATE random nonce (number used once)
			byte[] nonce = UseCases.generateRandomByteArray(nonceLength);

			GCMParameterSpec spec = new GCMParameterSpec(tagLength, nonce);

			cipher.init(Cipher.ENCRYPT_MODE, key.key, spec);

			byte[] byteCipher = cipher.doFinal(plaintext.getByteArray());
			SCCAlgorithmParameters param = new SCCAlgorithmParameters(nonce, tagLength, algo);
			SCCCiphertext c = new SCCCiphertext(byteCipher, param);
			return c;
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
				| InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
			return null;
		}
	}

	public static SCCCiphertext asymmetricEncryptWithParams(AbstractSCCKeyPair keyPair,
			PlaintextContainerInterface plaintext, String algo) {
		try {
			Cipher cipher = Cipher.getInstance(algo);
			cipher.init(Cipher.ENCRYPT_MODE, keyPair.publicKey);
			byte[] cipherTextBytes = cipher.doFinal(plaintext.getByteArray());
			SCCAlgorithmParameters parameters = new SCCAlgorithmParameters(algo);
			SCCCiphertext encrypted = new SCCCiphertext(cipherTextBytes, parameters);
			return encrypted;
		} catch (IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException
				| InvalidKeyException e) {
			e.printStackTrace();
		}
		return null;

	}

	public static SCCHash hashingWithParams(PlaintextContainerInterface plaintext, String algo) {
		try {
			MessageDigest messageDigest = MessageDigest.getInstance(algo);
			byte[] hashBytes = messageDigest.digest(plaintext.getByteArray());
			SCCAlgorithmParameters param = new SCCAlgorithmParameters(algo);
			SCCHash hash = new SCCHash(hashBytes, param);
			return hash;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return null;
	}

	public static SCCSignature signingingWithParams(AbstractSCCKeyPair keyPair, PlaintextContainerInterface plaintext,
			String algo) {
		try {
			Signature signature = Signature.getInstance(algo);
			signature.initSign((PrivateKey) keyPair.privateKey);
			signature.update(plaintext.getByteArray());
			byte[] s = signature.sign();
			SCCAlgorithmParameters parameters = new SCCAlgorithmParameters(algo, plaintext);
			SCCSignature signed = new SCCSignature(s, parameters);
			return signed;
		} catch (SignatureException | InvalidKeyException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * Generate Nonce with secure Random number generator
	 */
	public static byte[] generateRandomByteArray(int length) {
		try {
			// GENERATE random nonce (number used once)
			final byte[] nonce = new byte[length];
			SecureRandom random;
			random = SecureRandom.getInstanceStrong();
			random.nextBytes(nonce);
			return nonce;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}

	}


	public static SCCCiphertext fileEncryptWithParams(AbstractSCCKey key, String filepath, int nonceLength,
			int tagLength, String algo) {

		// ENCRYPTION
		Cipher cipher;
		try {
			cipher = Cipher.getInstance(algo);

			// GENERATE random nonce (number used once)
			byte[] nonce = UseCases.generateRandomByteArray(nonceLength);
			GCMParameterSpec spec = new GCMParameterSpec(tagLength, nonce);
			cipher.init(Cipher.ENCRYPT_MODE, key.key, spec);
			
			File inputFile = new File(filepath);
			FileInputStream inputStream = new FileInputStream(inputFile);
			byte[] inputBytes = new byte[(int) inputFile.length()];
			inputStream.read(inputBytes);
			
			FileOutputStream fileOutputStream = new FileOutputStream(filepath);
	        CipherOutputStream encryptedOutputStream = new CipherOutputStream(fileOutputStream, cipher);
	        InputStream stringInputStream = new ByteArrayInputStream(inputBytes);
	      
	        byte[] buffer = new byte[8192];
	        int nread;
	        while ((nread = stringInputStream.read(buffer)) > 0) {
	          encryptedOutputStream.write(buffer, 0, nread);
	        }
	        encryptedOutputStream.flush();
	        encryptedOutputStream.close();
	        inputStream.close();
			SCCAlgorithmParameters parameters = new SCCAlgorithmParameters(nonce, tagLength, algo);
			SCCCiphertext c = new SCCCiphertext(buffer, parameters);
			return c;
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | IOException | InvalidKeyException
				| InvalidAlgorithmParameterException e) {

			e.printStackTrace();
		}
		return null;
	}
	
	// Some experiments with COSE
	public void createMessage() {
		String nonce = "NONCE";
		String algo = "AES";
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
		// CBORObject algX = findA;
		System.out.println(o.findAttribute(HeaderKeys.Algorithm));
		System.out.println(o.getProtectedAttributes());
		System.out.println(o.findAttribute(n));
	}

	public static SCCPasswordHash passwordHashing(PlaintextContainerInterface password, String algo, byte[] salt, int keysize, int iterations) {
		try {
			KeySpec spec = new PBEKeySpec(password.getPlain().toCharArray(), salt, iterations, keysize);
			SecretKeyFactory factory = SecretKeyFactory.getInstance(algo);
			byte[]hash = factory.generateSecret(spec).getEncoded();
			SCCAlgorithmParameters param = new SCCAlgorithmParameters(algo, salt, keysize, iterations);
			return new SCCPasswordHash(hash, param);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			e.printStackTrace();
			return null;
		}
	}

}
