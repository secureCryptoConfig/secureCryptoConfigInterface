package main;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import COSE.AlgorithmID;
import COSE.AsymMessage;
import COSE.Attribute;
import COSE.CoseException;
import COSE.Encrypt0Message;
import COSE.HashMessage;
import COSE.HeaderKeys;
import COSE.OneKey;
import COSE.PasswordHashMessage;
import COSE.Sign1Message;

/**
 * Class for doing auxiliary processing for {@link SecureCryptoConfig}.
 * Especially creation/encoding to/from messages of COSE
 * 
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
			encrypt0Message.SetContent((byte[]) null);

			// byte[] encrypted = encrypt0Message.getEncryptedContent();

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
			hashMessage.SetContent((byte[]) null);
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
			m.SetContent((byte[]) null);
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
			m.SetContent((byte[]) null);
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
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws IllegalStateException
	 */
	protected static SCCCiphertext createAsymMessage(PlaintextContainerInterface plaintext, AlgorithmID id,
			AbstractSCCKey keyPair) throws IllegalStateException, InvalidKeySpecException, NoSuchAlgorithmException {
		try {
			SCCKey pair = (SCCKey) keyPair;
			AsymMessage asymMsg = new AsymMessage();
			asymMsg.SetContent(plaintext.toBytes());
			asymMsg.addAttribute(HeaderKeys.Algorithm, id.AsCBOR(), Attribute.PROTECTED);
			asymMsg.encrypt(new KeyPair(pair.getPublicKey(), pair.getPrivateKey()));
			asymMsg.SetContent((byte[]) null);

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
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	protected static SCCSignature createSignMessage(PlaintextContainerInterface plaintext, AbstractSCCKey key,
			AlgorithmID id) throws InvalidKeySpecException, NoSuchAlgorithmException {
		Sign1Message m = new Sign1Message();
		m.SetContent(plaintext.toBytes());
		SCCKey pair = (SCCKey) key;
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
