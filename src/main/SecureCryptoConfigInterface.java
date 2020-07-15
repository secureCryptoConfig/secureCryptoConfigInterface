package main;

import java.nio.charset.Charset;
import java.security.KeyPair;
import COSE.CoseException;
import main.SCCKey.SCCKeyAlgorithm;
import main.SCCKeyPair.SCCKeyPairAlgorithm;

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
	 * @return AbstractSCCCiphertext
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
	 * @param keyPair
	 * @return SCCCiphertext
	 */
	abstract AbstractSCCCiphertext encryptAsymmetric(AbstractSCCKeyPair pair);

	/**
	 * Signing of a plaintext with a specific key pair.
	 * @param keyPair
	 * @return AbstractSCCSignature
	 */
	abstract AbstractSCCSignature sign(AbstractSCCKeyPair keyPair);

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
	 * @param keyPair
	 * @return PlaintextContainerInterface
	 */
	abstract PlaintextContainerInterface decryptAsymmetric(AbstractSCCKeyPair keyPair);

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
	 * @param keyPair
	 * @return AbstractSCCCiphertext
	 */
	abstract AbstractSCCCiphertext reEncryptAsymmetric(AbstractSCCKeyPair keyPair);

}

abstract class AbstractSCCKey {

	byte[] key;
	SCCKeyAlgorithm algorithm;

	protected AbstractSCCKey(byte[] key, SCCKeyAlgorithm algorithm) {
		this.key = key;
		this.algorithm = algorithm;

	}

	/**
	 * Get byte[] representation of SCCKey
	 * @return byte[]
	 */
	abstract byte[] toBytes();

}

abstract class AbstractSCCKeyPair {
	byte[] privateKey, publicKey;
	SCCKeyPairAlgorithm algorithm;

	protected AbstractSCCKeyPair(byte[] publicKey, byte[] privateKey, SCCKeyPairAlgorithm algorithm) {
		this.publicKey = publicKey;
		this.privateKey = privateKey;
		this.algorithm = algorithm;
	}

	/**
	 * Get byte[] representation of public key
	 * @return byte[]
	 */
	abstract byte[] getPublicKeyBytes();
	
	/**
	 * Get byte[] representation of private key
	 * @return byte[]
	 */
	abstract byte[] getPrivateKeyBytes();

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
	 * @param keyPair
	 * @return boolean
	 */
	abstract boolean validateSignature(AbstractSCCKeyPair keyPair);

	/**
	 * Given a signature of a plaintext: the corresponding plaintext will be signed
	 * again with the current SCC.
	 * @param keyPair
	 * @param plaintext
	 * @return AbstractSCCSignature
	 * @throws CoseException
	 */
	abstract AbstractSCCSignature updateSignature(PlaintextContainerInterface plaintext, AbstractSCCKeyPair keyPair);

}


