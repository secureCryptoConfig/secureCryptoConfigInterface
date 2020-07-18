package main;

import java.nio.charset.Charset;
import COSE.CoseException;
import main.SCCKey.KeyType;

abstract interface SecureCryptoConfigInterface {

	// Symmetric Encryption
	
	/**
	 * Symmetric encryption with a certain key for a given plaintext.
	 * 
	 * @param key
	 * @param plaintext
	 * @return SCCCiphertext 
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
	 * @param keyPair: SCCKey
	 * @param plaintext
	 * @return SCCChiphertext
	 * @throws CoseException
	 */
	public AbstractSCCCiphertext encryptAsymmetric(AbstractSCCKey keyPair, PlaintextContainerInterface plaintext)
			throws CoseException;

	/**
	 * Asymmetric encryption with a certain key pair for a given plaintext.
	 * @param keyPair: SCCKey
	 * @param plaintext
	 * @return AbstractSCCCiphertext
	 * @throws CoseException
	 */
	public AbstractSCCCiphertext encryptAsymmetric(AbstractSCCKey keyPair, byte[] plaintext) throws CoseException;

	/**
	 * ReEncrypts a given ciphertext. Ciphertext will be first decrypted and then
	 * encrypted with the current SCC again.
	 * @param keyPair: SCCKey
	 * @param ciphertext
	 * @return AbstractSCCCiphertext
	 * @throws CoseException
	 */
	public AbstractSCCCiphertext reEncryptAsymmetric(AbstractSCCKey keyPair, AbstractSCCCiphertext ciphertext)
			throws CoseException;

	/**
	 * Asymmetric decryption with a certain key pair for a given ciphertext.
	 * @param keyPair: SCCKey
	 * @param ciphertext
	 * @return PlaintextContainerInterface
	 * @throws CoseException
	 */
	public PlaintextContainerInterface decryptAsymmetric(AbstractSCCKey keyPair, AbstractSCCCiphertext ciphertext)
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
	 * @param keyPair: SCCKey
	 * @param plaintext
	 * @return AbstractSCCSignature
	 * @throws CoseException
	 */
	public AbstractSCCSignature sign(AbstractSCCKey keyPair, PlaintextContainerInterface plaintext)
			throws CoseException;

	/**
	 * Signing of a plaintext with a specific key pair.
	 * @param keyPair: SCCKey
	 * @param plaintext
	 * @return AbstractSCCSignature
	 * @throws CoseException
	 */
	public AbstractSCCSignature sign(AbstractSCCKey keyPair, byte[] plaintext) throws CoseException;

	/**
	 * Given a signature of a plaintext: the corresponding plaintext will be signed
	 * again with the current SCC.
	 * @param keyPair: SCCKey
	 * @param plaintext
	 * @return AbstractSCCSignature
	 * @throws CoseException
	 */
	public AbstractSCCSignature updateSignature(AbstractSCCKey keyPair, PlaintextContainerInterface plaintext)
			throws CoseException;
	
	/**
	 * Given a signature of a plaintext: the corresponding plaintext will be signed
	 * again with the current SCC.
	 * @param keyPair: SCCKey
	 * @param plaintext
	 * @return AbstractSCCSignature
	 * @throws CoseException
	 */
	public AbstractSCCSignature updateSignature(AbstractSCCKey keyPair, byte[] plaintext)
			throws CoseException;
	
	/**
	 * A given signature is checked for validity
	 * @param keyPair: SCCKey
	 * @param signature
	 * @return boolean
	 */
	public boolean validateSignature(AbstractSCCKey keyPair, AbstractSCCSignature signature);
	
	public boolean validateSignature(AbstractSCCKey keyPair, byte[] signature);

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

	/**
	 * Get byte[] representation of PlaintextContainer
	 * @return byte[]
	 */
	abstract byte[] toBytes();

	/**
	 * Get String representation of PlaintextContainer depending on given Charset
	 * @param c
	 * @return String
	 */
	abstract String toString(Charset c);


	/**
	 * Look if a given hash for a specific plaintext is valid: plaintext will be hashed again and 
	 * compared if resulting hash is identical to the given one.
	 * @param hash
	 * @return boolean
	 */
	abstract boolean validateHash(AbstractSCCHash hash);

	/**
	 * Look if a given hash for a specific plaintext is valid: plaintext will be hashed again and 
	 * compared if resulting hash is identical to the given one.
	 * @param passwordhash
	 * @return boolean
	 */
	abstract boolean validatePasswordHash(AbstractSCCPasswordHash passwordHash);

	/**
	 * Symmetric encryption with a certain key for a given plaintext.
	 * @param key
	 * @return AbstractSCCCiphertext
	 */
	abstract AbstractSCCCiphertext encryptSymmetric(AbstractSCCKey key);

	/**
	 * Asymmetric encryption of PlaintextContainer with a certain key pair.
	 * @param keyPair: SCCKey
	 * @return SCCCiphertext
	 */
	abstract AbstractSCCCiphertext encryptAsymmetric(AbstractSCCKey pair);

	/**
	 * Signing of a plaintext with a specific key pair.
	 * @param keyPair: SCCKey
	 * @return AbstractSCCSignature
	 */
	abstract AbstractSCCSignature sign(AbstractSCCKey keyPair);

	/**
	 * Hashing of a given plaintext
	 * @return AbstractSCCHash
	 */
	abstract AbstractSCCHash hash();

	/**
	 * Given password will be hashed.
	 * @param password
	 * @return AbstractSCCPasswordHash
	 */
	abstract AbstractSCCPasswordHash passwordHash();

}

abstract class AbstractSCCCiphertext {
	
	byte[] msg;

	public AbstractSCCCiphertext(byte[] msg) {
		this.msg = msg;
	}

	/**
	 * Get byte[] representation of SCCCiphertext
	 * @return byte[]
	 */
	abstract byte[] toBytes();

	/**
	 * Get String representation of SCCCiphertext depending on given Charset
	 * @param c
	 * @return String
	 */
	abstract String toString(Charset c);

	/**
	 * Asymmetric decryption with a certain key pair for a given ciphertext.
	 * @param keyPair: SCCKey
	 * @return PlaintextContainerInterface
	 */
	abstract PlaintextContainerInterface decryptAsymmetric(AbstractSCCKey keyPair);

	/**
	 * Decryption of a given ciphertext.
	 * @param key
	 * @return PlaintextContainerInterface
	 */
	abstract PlaintextContainerInterface decryptSymmetric(AbstractSCCKey key);

	/**
	 * ReEncrypts a given ciphertext. Ciphertext will be first decrypted and then
	 * decrypted with the current used SCC again.
	 * @param key
	 * @return AbstractSCCCiphertext
	 */
	abstract AbstractSCCCiphertext reEncryptSymmetric(AbstractSCCKey key);

	/**
	 * ReEncrypts a given ciphertext. Ciphertext will be first decrypted and then
	 * encrypted with the current SCC again.
	 * @param keyPair: SCCKey
	 * @return AbstractSCCCiphertext
	 */
	abstract AbstractSCCCiphertext reEncryptAsymmetric(AbstractSCCKey keyPair);

}

abstract class AbstractSCCKey {

	KeyType type;
	byte[] key, privateKey, publicKey;
	String algorithm;
	
	protected AbstractSCCKey(KeyType type, byte[] publicKey, byte[] privateKey, String algorithm)
	{
		this.type = type;
		this.publicKey = publicKey;
		this.privateKey = privateKey;
		this.algorithm = algorithm;
		
	}
	
	protected AbstractSCCKey(KeyType type, byte[] key, String algorithm)
	{
		this.type = type;
		this.key = key;
		this.algorithm = algorithm;
		
	}

	/**
	 * Get byte[] representation of key
	 * @return byte[]: returns byte[] representation of key in case of a 'Symmetric' KeyType
	 */
	abstract byte[] toBytes();
	
	/**
	 * Get byte[] representation of public key
	 * @return byte[]: returns byte[] representation of public key in case of a 'Asymmetric' KeyType
	 */
	abstract byte[] getPublicKeyBytes();
	
	/**
	 * Get byte[] representation of private key
	 * @return byte[]: returns byte[] representation of private key in case of a 'Asymmetric' KeyType
	 */
	abstract byte[] getPrivateKeyBytes();
	
	/**
	 * Returns the algorithm used for key generation
	 * @return String: algorithm used for key generation
	 */
	abstract String getAlgorithm();

}

abstract class AbstractSCCKeyPair {
	
}

abstract class AbstractSCCHash {

	byte[] hashMsg;

	public AbstractSCCHash(byte[] hashMsg) {
		this.hashMsg = hashMsg;
	}

	/**
	 * Get byte[] representation of SCCHash
	 * @return byte[]
	 */
	abstract byte[] toBytes();
	
	/**
	 * Get String representation of SCCHash depending on given Charset
	 * @param c
	 * @return byte[]
	 */
	abstract String toString(Charset c);
	
	/**
	 * Look if a given hash for a specific plaintext is valid: plaintext will be hashed again and 
	 * compared if resulting hash is identical to the given one.
	 * @param plaintext
	 * @return boolean
	 */
	abstract boolean validateHash(PlaintextContainerInterface plaintext);

	/**
	 * Given a hash of a plaintext: the corresponding plaintext will be hashed again
	 * with the current SCC.
	 * @param plaintext
	 * @return AbstractSCCHash
	 */
	abstract AbstractSCCHash updateHash(PlaintextContainerInterface plaintext);
	

}

abstract class AbstractSCCPasswordHash {

	byte[] hashMsg;
	

	public AbstractSCCPasswordHash(byte[] hashMsg) {
		this.hashMsg = hashMsg;
	}

	/**
	 * Get byte[] representation of SCCPasswordHash
	 * @return byte[]
	 */
	abstract byte[] toBytes();
	
	/**
	 * Get String representation of SCCPasswordHash depending on given Charset
	 * @param c
	 * @return String
	 */
	abstract String toString(Charset c);
	
	/**
	 * Look if a given hash for a specific plaintext is valid: plaintext will be hashed again and 
	 * compared if resulting hash is identical to the given one.
	 * @param password
	 * @return boolean
	 */
	abstract boolean validatePasswordHash(PlaintextContainerInterface password);

}

abstract class AbstractSCCSignature {
	byte[] signatureMsg;

	public AbstractSCCSignature(byte[] signatureMasg) {
		this.signatureMsg = signatureMasg;
	}

	/**
	 * Get byte[] representation of SCCPasswordHash
	 * @return byte[]
	 */
	abstract byte[] toBytes();

	/**
	 * Get String representation of SCCSignature depending on given Charset
	 * @param c
	 * @return String
	 */
	abstract String toString(Charset c);

	/**
	 * A given signature is checked for validity
	 * @param keyPair: SCCKey
	 * @return boolean
	 */
	abstract boolean validateSignature(AbstractSCCKey keyPair);

	/**
	 * Given a signature of a plaintext: the corresponding plaintext will be signed
	 * again with the current SCC.
	 * @param keyPair: SCCKey
	 * @param plaintext
	 * @return AbstractSCCSignature
	 * @throws CoseException
	 */
	abstract AbstractSCCSignature updateSignature(PlaintextContainerInterface plaintext, AbstractSCCKey keyPair);

}


