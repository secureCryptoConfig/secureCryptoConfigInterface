package main;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
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

	protected static SCCCiphertext fileEncryptWithParams(AbstractSCCKey key, String filepath, AlgorithmID algo) {

		try {
			
			File inputFile = new File(filepath);
			FileInputStream inputStream = new FileInputStream(inputFile);
			byte[] inputBytes = new byte[(int) inputFile.length()];
			inputStream.read(inputBytes);

			FileOutputStream fileOutputStream = new FileOutputStream(filepath);
			InputStream stringInputStream = new ByteArrayInputStream(inputBytes);

			Encrypt0Message encrypt0Message = new Encrypt0Message();
			byte[] plain = new byte[8192];
			stringInputStream.read(plain);
		
				encrypt0Message.SetContent(plain);

				encrypt0Message.addAttribute(HeaderKeys.Algorithm, algo.AsCBOR(), Attribute.PROTECTED);

				encrypt0Message.encrypt(key.key);
				byte[] encrypted = encrypt0Message.getEncryptedContent();
				fileOutputStream.write(encrypted);
				
			
			fileOutputStream.close();
			inputStream.close();
			SCCCiphertext s = new SCCCiphertext(new PlaintextContainer(plain), encrypted, key, encrypt0Message.EncodeToBytes());
			return s;
		} catch (IOException | CoseException e) {

			e.printStackTrace();
			return null;
		}
		
	}

	protected static SCCCiphertextOutputStream fileEncryptStream(AbstractSCCKey key, AlgorithmID algo,
			InputStream inputStream) {
		ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
		try {

			byte[] buffer = new byte[8192];
			Encrypt0Message encrypt0Message = new Encrypt0Message();
			inputStream.read(buffer);
			inputStream.read(buffer);

			encrypt0Message.SetContent(buffer);

			encrypt0Message.addAttribute(HeaderKeys.Algorithm, algo.AsCBOR(), Attribute.PROTECTED);

			encrypt0Message.encrypt(key.key);
			byte[] encrypted = encrypt0Message.getEncryptedContent();

			byteArrayOutputStream.write(encrypted);
			return new SCCCiphertextOutputStream(byteArrayOutputStream);

		} catch (IOException | CoseException e) {
			e.printStackTrace();
			return null;
		}

	}

	// creation of COSE msg for symmetric Encryption
	protected static SCCCiphertext createMessage(PlaintextContainerInterface plaintext, AbstractSCCKey key,
			AlgorithmID id) {
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
	protected static SCCHash createHashMessage(PlaintextContainer plaintext, AlgorithmID id) {
		try {
			HashMessage hashMessage = new HashMessage();
			hashMessage.SetContent(plaintext.getByteArray());

			hashMessage.addAttribute(HeaderKeys.Algorithm, id.AsCBOR(), Attribute.PROTECTED);

			hashMessage.hash();

			return new SCCHash(plaintext, new PlaintextContainer(hashMessage.getHashedContent()),
					hashMessage.EncodeToBytes());

		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

	// Cose msg for Hashing
	protected static SCCPasswordHash createPasswordHashMessage(PlaintextContainerInterface password, AlgorithmID id) {

		try {
			PasswordHashMessage m = new PasswordHashMessage();
			m.SetContent(password.getByteArray());
			m.addAttribute(HeaderKeys.Algorithm, id.AsCBOR(), Attribute.PROTECTED);
			m.passwordHash();
			PlaintextContainer hashed = new PlaintextContainer(m.getHashedContent());
			return new SCCPasswordHash((PlaintextContainer) password, hashed, m.EncodeToBytes());

		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

	protected static SCCPasswordHash createPasswordHashMessageSalt(PlaintextContainerInterface password, AlgorithmID id,
			byte[] salt) {
		try {
			PasswordHashMessage m = new PasswordHashMessage();
			m.SetContent(password.getByteArray());
			m.addAttribute(HeaderKeys.Algorithm, id.AsCBOR(), Attribute.PROTECTED);
			m.passwordHashWithSalt(salt);

			PlaintextContainer hashed = new PlaintextContainer(m.getHashedContent());
			return new SCCPasswordHash((PlaintextContainer) password, hashed, m.EncodeToBytes());
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

	// Cose msg for Asym
	protected static SCCCiphertext createAsymMessage(PlaintextContainerInterface plaintext, AlgorithmID id,
			AbstractSCCKeyPair keyPair) {
		try {
			AsymMessage m3 = new AsymMessage();
			m3.SetContent(plaintext.getByteArray());
			m3.addAttribute(HeaderKeys.Algorithm, id.AsCBOR(), Attribute.PROTECTED);
			m3.encrypt(keyPair.getKeyPair());
			byte[] encrypted = m3.getEncryptedContent();

			return new SCCCiphertext(plaintext, encrypted, keyPair, m3.EncodeToBytes());
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

	protected static PlaintextContainer decodeMessage(AbstractSCCKey key, AbstractSCCCiphertext sccciphertext) {
		try {
			Encrypt0Message msg = (Encrypt0Message) Encrypt0Message.DecodeFromBytes(sccciphertext.msg);
			// Encrypt0Message msg = sccciphertext.msg;
			return new PlaintextContainer(msg.decrypt(key.getByteArray()));
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}

	}

	protected static SCCSignature createSignMessage(PlaintextContainerInterface plaintext, AbstractSCCKeyPair key,
			AlgorithmID id) {
		Sign1Message m = new Sign1Message();
		m.SetContent(plaintext.getByteArray());
		try {
			m.addAttribute(HeaderKeys.Algorithm, AlgorithmID.ECDSA_512.AsCBOR(), Attribute.PROTECTED);
			OneKey oneKey = new OneKey(key.getPublic(), key.getPrivate());
			m.sign(oneKey);
			return new SCCSignature((PlaintextContainer) plaintext, new PlaintextContainer(m.getSignature()),
					m.EncodeToBytes());
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

}
