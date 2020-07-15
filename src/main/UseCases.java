package main;

import COSE.*;
import main.SCCKeyPair;

/**
 * Class for doing auxiliary functionality for the SecureCryptoConfig class. 
 * Especially creation/encoding to/from Messages of COSE
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
			encrypt0Message.SetContent((byte[])null);
			
			//byte[] encrypted = encrypt0Message.getEncryptedContent();

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
			hashMessage.SetContent((byte[])null);
			return new SCCHash(hashMessage.EncodeToBytes());

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
			m.SetContent((byte[])null);
			return new SCCPasswordHash(m.EncodeToBytes());

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
			m.SetContent((byte[])null);
			return new SCCPasswordHash(m.EncodeToBytes());
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
			SCCKeyPair pair = (SCCKeyPair) keyPair;
			AsymMessage asymMsg = new AsymMessage();
			asymMsg.SetContent(plaintext.toBytes());
			asymMsg.addAttribute(HeaderKeys.Algorithm, id.AsCBOR(), Attribute.PROTECTED);
			asymMsg.encrypt(pair.makeKeyPair());
			asymMsg.SetContent((byte[])null);

			return new SCCCiphertext(asymMsg.EncodeToBytes());
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
		SCCKeyPair pair = (SCCKeyPair) key;
		try {
			m.addAttribute(HeaderKeys.Algorithm, AlgorithmID.ECDSA_512.AsCBOR(), Attribute.PROTECTED);
			OneKey oneKey = new OneKey(pair.getPublicKey(), pair.getPrivateKey());
			m.sign(oneKey);
			
			return new SCCSignature(m.EncodeToBytes());
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}
}
