package main;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
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

import COSE.*;

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

	// creation of COSE msg
	public static SCCCiphertext createMessage(String plaintext, Key key, AlgorithmID id) {
		try {
			Encrypt0Message encrypt0Message = new Encrypt0Message();
			encrypt0Message.SetContent(plaintext.getBytes());

			encrypt0Message.addAttribute(HeaderKeys.Algorithm, id.AsCBOR(), Attribute.PROTECTED);
			
			encrypt0Message.encrypt(key.getEncoded());
			return new SCCCiphertext(encrypt0Message.EncodeToBytes());

		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	// creation of COSE msg asymm try
	/**
		public static SCCCiphertext createMessageAsym(String plaintext, OneKey key, AlgorithmID id) {
			try {
				Encrypt0Message encrypt0Message = new Encrypt0Message();
				encrypt0Message.SetContent(plaintext.getBytes());

				encrypt0Message.addAttribute(HeaderKeys.Algorithm, id.AsCBOR(), Attribute.PROTECTED);
				
				encrypt0Message.encrypt(key.EncodeToBytes());
				return new SCCCiphertext(encrypt0Message.getEncryptedContent(), encrypt0Message);

			} catch (CoseException e) {
				e.printStackTrace();
				return null;
			}
		}**/

	public static PlaintextContainer decodeMessage(AbstractSCCKey key, AbstractSCCCiphertext sccciphertext) {
		try {
			Encrypt0Message msg = (Encrypt0Message) Encrypt0Message.DecodeFromBytes(sccciphertext.ciphertext);
			//Encrypt0Message msg = sccciphertext.msg;
			String s = new String(msg.decrypt(key.key.getEncoded()), StandardCharsets.UTF_8);
			return new PlaintextContainer(s);
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}

	}

	public static SCCPasswordHash passwordHashing(PlaintextContainerInterface password, String algo, byte[] salt,
			int keysize, int iterations) {
		try {
			KeySpec spec = new PBEKeySpec(password.getPlain().toCharArray(), salt, iterations, keysize);
			SecretKeyFactory factory = SecretKeyFactory.getInstance(algo);
			byte[] hash = factory.generateSecret(spec).getEncoded();
			SCCAlgorithmParameters param = new SCCAlgorithmParameters(algo, salt, keysize, iterations);
			return new SCCPasswordHash(hash, param);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	public static SCCSignature createSignMessage(PlaintextContainerInterface plaintext, OneKey key, AlgorithmID id) {
		Sign1Message m = new Sign1Message();
		m.SetContent(plaintext.getByteArray());
		try {
			m.addAttribute(HeaderKeys.Algorithm, AlgorithmID.ECDSA_512.AsCBOR(), Attribute.PROTECTED);
			m.sign(key);
			SCCAlgorithmParameters p = null;
			return new SCCSignature(m.EncodeToBytes(), p);
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

}
