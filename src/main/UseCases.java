package main;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;

import COSE.*;

public class UseCases {

	
	// Method for getting file content. Content needed for comparing file encryption
	// test
	public static String readFile(String filepath) {
		String s = "";
		try {
			File file = new File(filepath);
			BufferedReader br = new BufferedReader(new FileReader(file));
			String st;
			while ((st = br.readLine()) != null) {
				s = s + st + "\n";
			}
			br.close();
			return s;
		} catch (IOException e) {
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
			cipher.init(Cipher.ENCRYPT_MODE, key.getSecretKey(), spec);

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

	public static SCCCiphertextOutputStream fileEncryptStream(AbstractSCCKey key, OutputStream outputStream, int nonceLength,
			int tagLength, String algo) {
	
		Cipher cipher;
		try {
			cipher = Cipher.getInstance(algo);

			// GENERATE random nonce (number used once)
			byte[] nonce = UseCases.generateRandomByteArray(nonceLength);
			GCMParameterSpec spec = new GCMParameterSpec(tagLength, nonce);
			cipher.init(Cipher.ENCRYPT_MODE, key.getSecretKey(), spec);

			SCCAlgorithmParameters param = new SCCAlgorithmParameters(nonce, tagLength, algo);
			SCCCiphertextOutputStream stream = new SCCCiphertextOutputStream(outputStream, cipher, param);
			return stream;
			
			} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
						| InvalidAlgorithmParameterException e) {

				e.printStackTrace();
			}
			return null;
	}

	public static SCCPasswordHash passwordHashing(PlaintextContainerInterface password, String algo, byte[] salt,
			int keysize, int iterations) {
		try {
			KeySpec spec = new PBEKeySpec(password.getBase64().toCharArray(), salt, iterations, keysize);
			SecretKeyFactory factory = SecretKeyFactory.getInstance(algo);
			byte[] hash = factory.generateSecret(spec).getEncoded();
			// SCCAlgorithmParameters param = new SCCAlgorithmParameters(algo, salt,
			// keysize, iterations);
			// return new SCCPasswordHash(hash, param);
			return new SCCPasswordHash(hash);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			e.printStackTrace();
			return null;
		}
	}

	// creation of COSE msg for symmetric Encryption
	public static SCCCiphertext createMessage(PlaintextContainerInterface plaintext, AbstractSCCKey key, AlgorithmID id) {
		try {
			Encrypt0Message encrypt0Message = new Encrypt0Message();
			encrypt0Message.SetContent(plaintext.getByteArray());

			encrypt0Message.addAttribute(HeaderKeys.Algorithm, id.AsCBOR(), Attribute.PROTECTED);

			encrypt0Message.encrypt(key.key);
			byte[] encrypted = encrypt0Message.getEncryptedContent();
			
			return new SCCCiphertext(plaintext, encrypted, key, encrypt0Message.EncodeToBytes());
			

		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

	// Cose msg for Hashing
	public static SCCHash createHashMessage(PlaintextContainerInterface plaintext, AlgorithmID id) {
		try {
			HashMessage hashMessage = new HashMessage();
			hashMessage.SetContent(plaintext.getByteArray());
			hashMessage.addAttribute(HeaderKeys.Algorithm, id.AsCBOR(), Attribute.PROTECTED);

			hashMessage.hash();
			return new SCCHash(hashMessage.EncodeToBytes());

		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

	// Cose msg for Hashing
	public static SCCPasswordHash createPasswordHashMessage(PlaintextContainerInterface password, AlgorithmID id) {

		try {
			PasswordHashMessage m = new PasswordHashMessage();
			m.SetContent(password.getByteArray());
			m.addAttribute(HeaderKeys.Algorithm, id.AsCBOR(), Attribute.PROTECTED);
			m.passwordHash();

			return new SCCPasswordHash(m.EncodeToBytes());

		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

	public static SCCPasswordHash createPasswordHashMessageSalt(PlaintextContainerInterface password, AlgorithmID id, byte[] salt) {
		try {
			PasswordHashMessage m = new PasswordHashMessage();
			m.SetContent(password.getByteArray());
			m.addAttribute(HeaderKeys.Algorithm, id.AsCBOR(), Attribute.PROTECTED);
			m.passwordHashWithSalt(salt);

			return new SCCPasswordHash(m.EncodeToBytes());

		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

	// Cose msg for Asym
	public static SCCCiphertext createAsymMessage(PlaintextContainerInterface plaintext, AlgorithmID id,
			AbstractSCCKeyPair keyPair) {
		try {
			AsymMessage m3 = new AsymMessage();
			m3.SetContent(plaintext.getByteArray());
			m3.addAttribute(HeaderKeys.Algorithm, id.AsCBOR(), Attribute.PROTECTED);
			m3.encrypt(keyPair.pair);
			byte[] encrypted = m3.getEncryptedContent();
			
			return new SCCCiphertext(plaintext, encrypted, keyPair, m3.EncodeToBytes());
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

	public static PlaintextContainer decodeMessage(AbstractSCCKey key, AbstractSCCCiphertext sccciphertext) {
		try {
			Encrypt0Message msg = (Encrypt0Message) Encrypt0Message.DecodeFromBytes(sccciphertext.msg);
			// Encrypt0Message msg = sccciphertext.msg;
			return new PlaintextContainer(msg.decrypt(key.getByteArray()));
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}

	}

	public static SCCSignature createSignMessage(PlaintextContainerInterface plaintext, AbstractSCCKeyPair key, AlgorithmID id) {
		Sign1Message m = new Sign1Message();
		m.SetContent(plaintext.getByteArray());
		try {
			m.addAttribute(HeaderKeys.Algorithm, AlgorithmID.ECDSA_512.AsCBOR(), Attribute.PROTECTED);
			OneKey oneKey = new OneKey(key.getPublic(), key.getPrivate());
			m.sign(oneKey);
			return new SCCSignature(m.EncodeToBytes());
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

	

}
