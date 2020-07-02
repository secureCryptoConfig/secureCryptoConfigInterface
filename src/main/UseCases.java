package main;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import COSE.*;

/**
 * Class for doing auxiliary functionality for the SecureCryptoConfig class. 
 * @author Lisa
 *
 */
public class UseCases {

	/**
	 * Creation of COSE Encrypt0Message for symmetric Encryption
	 * 
	 * @param plaintext
	 * @param key
	 * @param id
	 * @return SCCCiphertext
	 */
	protected static SCCCiphertext createMessage(PlaintextContainerInterface plaintext, AbstractSCCKey key,
			AlgorithmID id) {
		try {
			Encrypt0Message encrypt0Message = new Encrypt0Message();
			encrypt0Message.SetContent(plaintext.toBytes());

			encrypt0Message.addAttribute(HeaderKeys.Algorithm, id.AsCBOR(), Attribute.PROTECTED);

			encrypt0Message.encrypt(key.key);
			byte[] encrypted = encrypt0Message.getEncryptedContent();

			return new SCCCiphertext(encrypt0Message.EncodeToBytes());

		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Creation of COSE HashMessage for hashing
	 * 
	 * @param plaintext
	 * @param id
	 * @return SCCHash
	 */
	protected static SCCHash createHashMessage(PlaintextContainer plaintext, AlgorithmID id) {
		try {
			HashMessage hashMessage = new HashMessage();
			hashMessage.SetContent(plaintext.toBytes());

			hashMessage.addAttribute(HeaderKeys.Algorithm, id.AsCBOR(), Attribute.PROTECTED);

			hashMessage.hash();

			return new SCCHash(plaintext, hashMessage.EncodeToBytes());

		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Creation of COSE PasswordHashMessage for password Hashing
	 * 
	 * @param password
	 * @param id
	 * @return SCCPasswordHash
	 */
	protected static SCCPasswordHash createPasswordHashMessage(PlaintextContainerInterface password, AlgorithmID id) {

		try {
			PasswordHashMessage m = new PasswordHashMessage();
			m.SetContent(password.toBytes());
			m.addAttribute(HeaderKeys.Algorithm, id.AsCBOR(), Attribute.PROTECTED);
			m.passwordHash();
			PlaintextContainer hashed = new PlaintextContainer(m.getHashedContent());
			return new SCCPasswordHash((PlaintextContainer) password, hashed, m.EncodeToBytes());

		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Creation of COSE PasswordHashMessage for password hashing with existing salt
	 * value
	 * 
	 * @param password
	 * @param id
	 * @param salt
	 * @return SCCPasswordHash
	 */
	protected static SCCPasswordHash createPasswordHashMessageSalt(PlaintextContainerInterface password, AlgorithmID id,
			byte[] salt) {
		try {
			PasswordHashMessage m = new PasswordHashMessage();
			m.SetContent(password.toBytes());
			m.addAttribute(HeaderKeys.Algorithm, id.AsCBOR(), Attribute.PROTECTED);
			m.passwordHashWithSalt(salt);

			PlaintextContainer hashed = new PlaintextContainer(m.getHashedContent());
			return new SCCPasswordHash((PlaintextContainer) password, hashed, m.EncodeToBytes());
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Creation of COSE AsymMessage for asymmetric Encryption
	 * 
	 * @param plaintext
	 * @param id
	 * @param keyPair
	 * @return SCCCiphertext
	 */
	protected static SCCCiphertext createAsymMessage(PlaintextContainerInterface plaintext, AlgorithmID id,
			AbstractSCCKeyPair keyPair) {
		try {
			AsymMessage m3 = new AsymMessage();
			m3.SetContent(plaintext.toBytes());
			m3.addAttribute(HeaderKeys.Algorithm, id.AsCBOR(), Attribute.PROTECTED);
			m3.encrypt(keyPair.pair);
			byte[] encrypted = m3.getEncryptedContent();

			return new SCCCiphertext(m3.EncodeToBytes());
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Creation of COSE Sign1Message for signing
	 * 
	 * @param plaintext
	 * @param key
	 * @param id
	 * @return SCCSignature
	 */
	protected static SCCSignature createSignMessage(PlaintextContainerInterface plaintext, AbstractSCCKeyPair key,
			AlgorithmID id) {
		Sign1Message m = new Sign1Message();
		m.SetContent(plaintext.toBytes());
		try {
			m.addAttribute(HeaderKeys.Algorithm, AlgorithmID.ECDSA_512.AsCBOR(), Attribute.PROTECTED);
			OneKey oneKey = new OneKey(key.pair.getPublic(), key.pair.getPrivate());
			m.sign(oneKey);
			return new SCCSignature((PlaintextContainer) plaintext, (SCCKeyPair) key, m.EncodeToBytes());
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Encryption of content of a given file with given parameters. Ciphertext will
	 * overwrite the file content.
	 * 
	 * @param key
	 * @param filepath
	 * @param algo
	 * @return
	 */
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
			SCCCiphertext s = new SCCCiphertext(encrypt0Message.EncodeToBytes());
			return s;
		} catch (IOException | CoseException e) {

			e.printStackTrace();
			return null;
		}

	}

	/**
	 * Encryption of content of a given Inputstream. 
	 * 
	 * @param key
	 * @param filepath
	 * @param algo
	 * @return SCCCiphertextOutputStream
	 */
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
}
