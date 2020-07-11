package main;

import java.nio.charset.Charset;
import java.security.KeyPair;
import COSE.CoseException;
import main.SCCKey.SCCKeyAlgorithm;

abstract interface SecureCryptoConfigInterface {

	// Symmetric Encryption
	
	/**
	 * Symmetric encryption with a certain key for a given plaintext.
	 * @param key
	 * @param plaintext
	 * @return AbstractSCCCiphertext
	 * @throws CoseException
	 */
	public AbstractSCCCiphertext encryptSymmetric(AbstractSCCKey key, PlaintextContainerInterface plaintext)
			throws CoseException;
	
	/**
	 * Symmetric encryption with a certain key for a given plaintext.
	 * @param key
	 * @param plaintext
	 * @return AbstractSCCCiphertext
	 * @throws CoseException
	 */
	public AbstractSCCCiphertext encryptSymmetric(AbstractSCCKey key, byte[] plaintext) throws CoseException;

	/**
	 * ReEncrypts a given ciphertext. Ciphertext will be first decrypted and then
	 * decrypted with the current used SCC again.
	 * @param key
	 * @param ciphertext
	 * @return AbstractSCCCiphertext
	 * @throws CoseException
	 */
	public AbstractSCCCiphertext reEncryptSymmetric(AbstractSCCKey key, AbstractSCCCiphertext ciphertext)
			throws CoseException;

	/**
	 * Decryption of a given ciphertext.
	 * @param key
	 * @param sccciphertext
	 * @return PlaintextContainerInterface
	 * @throws CoseException
	 */
	public PlaintextContainerInterface decryptSymmetric(AbstractSCCKey key, AbstractSCCCiphertext sccciphertext)
			throws CoseException;

	// Asymmetric
	
	/**
	 * Asymmetric encryption with a certain key pair for a given plaintext.
	 * @param keyPair
	 * @param plaintext
	 * @return SCCChiphertext
	 * @throws CoseException
	 */
	public AbstractSCCCiphertext encryptAsymmetric(AbstractSCCKeyPair keyPair, PlaintextContainerInterface plaintext)
			throws CoseException;

	/**
	 * Asymmetric encryption with a certain key pair for a given plaintext.
	 * @param keyPair
	 * @param plaintext
	 * @return
	 * @throws CoseException
	 */
	public AbstractSCCCiphertext encryptAsymmetric(AbstractSCCKeyPair keyPair, byte[] plaintext) throws CoseException;

	/**
	 * ReEncrypts a given ciphertext. Ciphertext will be first decrypted and then
	 * encrypted with the current SCC again.
	 * @param keyPair
	 * @param ciphertext
	 * @return AbstractSCCCiphertext
	 * @throws CoseException
	 */
	public AbstractSCCCiphertext reEncryptAsymmetric(AbstractSCCKeyPair keyPair, AbstractSCCCiphertext ciphertext)
			throws CoseException;

	/**
	 * Asymmetric decryption with a certain key pair for a given ciphertext.
	 * @param keyPair
	 * @param ciphertext
	 * @return PlaintextContainerInterface
	 * @throws CoseException
	 */
	public PlaintextContainerInterface decryptAsymmetric(AbstractSCCKeyPair keyPair, AbstractSCCCiphertext ciphertext)
			throws CoseException;

	// Hashing
	
	/**
	 * Hashing of a given plaintext
	 * @param plaintext
	 * @return AbstractSCCHash
	 * @throws CoseException
	 */
	public AbstractSCCHash hash(PlaintextContainerInterface plaintext) throws CoseException;

	/**
	 * Hashing of a given plaintext
	 * @param plaintext
	 * @return AbstractSCCHash
	 * @throws CoseException
	 */
	public AbstractSCCHash hash(byte[] plaintext) throws CoseException;

	/**
	 * Given a hash of a plaintext: the corresponding plaintext will be hashed again
	 * with the current SCC.
	 * @param plaintext
	 * @param hash
	 * @return AbstractSCCHash
	 * @throws CoseException
	 */
	public AbstractSCCHash updateHash(PlaintextContainerInterface plaintext, AbstractSCCHash hash) throws CoseException;

	/**
	 * Given a hash of a plaintext: the corresponding plaintext will be hashed again
	 * with the current SCC.
	 * @param plaintext
	 * @param hash
	 * @return AbstractSCCHash
	 * @throws CoseException
	 */
	public AbstractSCCHash updateHash(byte[] plaintext, AbstractSCCHash hash) throws CoseException;

	/**
	 * Look if a given hash for a specific plaintext is valid: plaintext will be hashed again and 
	 * compared if resulting hash is identical to the given one.
	 * @param plaintext
	 * @param hash
	 * @return boolean
	 * @throws CoseException
	 */
	public boolean validateHash(PlaintextContainerInterface plaintext, AbstractSCCHash hash) throws CoseException;

	/**
	 * Look if a given hash for a specific plaintext is valid: plaintext will be hashed again and 
	 * compared if resulting hash is identical to the given one.
	 * @param plaintext
	 * @param hash
	 * @return boolean
	 * @throws CoseException
	 */
	public boolean validateHash(byte[] plaintext, AbstractSCCHash hash) throws CoseException;

	// Digital Signature
	
	/**
	 * Signing of a plaintext with a specific key pair.
	 * @param keyPair
	 * @param plaintext
	 * @return AbstractSCCSignature
	 * @throws CoseException
	 */
	public AbstractSCCSignature sign(AbstractSCCKeyPair keyPair, PlaintextContainerInterface plaintext)
			throws CoseException;

	/**
	 * Signing of a plaintext with a specific key pair.
	 * @param keyPair
	 * @param plaintext
	 * @return AbstractSCCSignature
	 * @throws CoseException
	 */
	public AbstractSCCSignature sign(AbstractSCCKeyPair keyPair, byte[] plaintext) throws CoseException;

	/**
	 * Given a signature of a plaintext: the corresponding plaintext will be signed
	 * again with the current SCC.
	 * @param keyPair
	 * @param plaintext
	 * @return AbstractSCCSignature
	 * @throws CoseException
	 */
	public AbstractSCCSignature updateSignature(AbstractSCCKeyPair keyPair, PlaintextContainerInterface plaintext)
			throws CoseException;
	
	/**
	 * Given a signature of a plaintext: the corresponding plaintext will be signed
	 * again with the current SCC.
	 * @param keyPair
	 * @param plaintext
	 * @return AbstractSCCSignature
	 * @throws CoseException
	 */
	public AbstractSCCSignature updateSignature(AbstractSCCKeyPair keyPair, byte[] plaintext)
			throws CoseException;
	
	/**
	 * A given signature is checked for validity
	 * @param keyPair
	 * @param signature
	 * @return boolean
	 */
	public boolean validateSignature(AbstractSCCKeyPair keyPair, AbstractSCCSignature signature);

	// Password Hashing
	
	/**
	 * Given password will be hashed.
	 * @param password
	 * @return AbstractSCCPasswordHash
	 * @throws CoseException
	 */
	public AbstractSCCPasswordHash passwordHash(PlaintextContainerInterface password) throws CoseException;

	/**
	 * Given password will be hashed.
	 * @param password
	 * @return AbstractSCCPasswordHash
	 * @throws CoseException
	 */
	public AbstractSCCPasswordHash passwordHash(byte[] password) throws CoseException;

	/**
	 * Look if a given hash for a specific plaintext is valid: plaintext will be hashed again and 
	 * compared if resulting hash is identical to the given one.
	 * @param password
	 * @param passwordhash
	 * @return boolean
	 * @throws CoseException
	 */
	public boolean validatePasswordHash(PlaintextContainerInterface password, AbstractSCCPasswordHash passwordhash)
			throws CoseException;

	/**
	 * Look if a given hash for a specific plaintext is valid: plaintext will be hashed again and 
	 * compared if resulting hash is identical to the given one.
	 * @param password
	 * @param passwordhash
	 * @return boolean
	 * @throws CoseException
	 */
	public boolean validatePasswordHash(byte[] password, AbstractSCCPasswordHash passwordhash)
			throws CoseException;
}

abstract interface PlaintextContainerInterface {

	abstract byte[] toBytes();

	abstract String toString(Charset c);

	abstract boolean validateHash(AbstractSCCHash hash);

	abstract boolean validatePasswordHash(AbstractSCCPasswordHash passwordHash);

	abstract SCCCiphertext encryptSymmetric(AbstractSCCKey key);

	abstract SCCCiphertext encryptAsymmetric(AbstractSCCKeyPair pair);

	abstract SCCSignature sign(AbstractSCCKeyPair keyPair);

	abstract SCCHash hash();

	abstract SCCPasswordHash passwordHash();

}

abstract class AbstractSCCCiphertext {
	
	byte[] msg;

	public AbstractSCCCiphertext(byte[] msg) {
		this.msg = msg;
	}

	abstract byte[] toBytes();

	abstract String toString(Charset c);

	abstract PlaintextContainer decryptAsymmetric(AbstractSCCKeyPair keyPair);

	abstract PlaintextContainer decryptSymmetric(AbstractSCCKey key);

	abstract SCCCiphertext reEncryptSymmetric(AbstractSCCKey key);

	abstract SCCCiphertext reEncryptAsymmetric(AbstractSCCKeyPair keyPair);

}

abstract class AbstractSCCKey {

	byte[] key;
	SCCKeyAlgorithm algorithm;

	protected AbstractSCCKey(byte[] key, SCCKeyAlgorithm algorithm) {
		this.key = key;
		this.algorithm = algorithm;

	}

	abstract byte[] toBytes();

}

abstract class AbstractSCCKeyPair {
	KeyPair pair;

	protected AbstractSCCKeyPair(KeyPair pair) {
		this.pair = pair;
	}

	abstract byte[] getPublicKeyBytes();

	abstract byte[] getPrivateKeyBytes();

}

abstract class AbstractSCCHash {

	byte[] hashMsg;

	public AbstractSCCHash(byte[] hashMsg) {
		this.hashMsg = hashMsg;
	}

	abstract byte[] toBytes();
	
	abstract String toString(Charset c);
	
	abstract boolean validateHash(PlaintextContainerInterface plaintext);

	abstract SCCHash updateHash(PlaintextContainerInterface plaintext);
	

}

abstract class AbstractSCCPasswordHash {

	byte[] hashMsg;
	

	public AbstractSCCPasswordHash(byte[] hashMsg) {
		this.hashMsg = hashMsg;
	}

	abstract byte[] toBytes();
	
	abstract String toString(Charset c);
	
	abstract boolean validatePasswordHash(PlaintextContainerInterface password);

}

abstract class AbstractSCCSignature {
	byte[] signatureMsg;

	// keyPair, plaintext
	public AbstractSCCSignature(byte[] signatureMasg) {
		this.signatureMsg = signatureMasg;
	}

	abstract byte[] toBytes();

	abstract String toString(Charset c);

	abstract boolean validateSignature(AbstractSCCKeyPair keyPair);

	abstract SCCSignature updateSignature(PlaintextContainerInterface plaintext, AbstractSCCKeyPair keyPair);

}

/*
 * abstract class AbstractSCCCiphertextOutputStream {
 * 
 * abstract ByteArrayOutputStream getStream();
 * 
 * abstract String getEncryptedContent();
 * 
 * abstract byte[] getEncryptedBytes();
 * 
 * }
 * 
 * abstract class AbstractPlaintextOutputStream {
 * 
 * }
 */
