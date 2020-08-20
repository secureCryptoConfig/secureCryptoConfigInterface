package org.securecryptoconfig;

import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.util.Base64;

import org.securecryptoconfig.SCCKey.KeyType;

import COSE.CoseException;

/**
 * Interface that defines which methods should be used for cryptography
 * operations.
 * 
 * @author Kai
 *
 */
abstract interface SecureCryptoConfigInterface {

	// Symmetric Encryption

	/**
	 * Symmetric encryption with a certain {@link SCCKey} for a given plaintext based on the current Secure Crypto Config file.
	 * 
	 * A new {@link SCCKey} can be created with
	 * {@link SCCKey#createKey(org.securecryptoconfig.SCCKey.KeyUseCase)} with
	 * {@link SCCKey.KeyUseCase#SymmetricEncryption} Alternatively it is also
	 * possible to create a key derived from a password with
	 * {@link SCCKey#createSymmetricKeyWithPassword(byte[])}
	 * 
	 * @param key: {@link SCCKey}
	 * @param plaintext: as {@link PlaintextContainer}
	 * @return {@link SCCCiphertext}
	 * @throws CoseException
	 * @throws InvalidKeyException : If {@link SCCKey} has not the
	 *                             {@link KeyType#Symmetric}
	 * @throws SCCException 
	 */
	public AbstractSCCCiphertext encryptSymmetric(AbstractSCCKey key, PlaintextContainerInterface plaintext)
			throws CoseException, InvalidKeyException, SCCException;

	/**
	 * Symmetric encryption with a certain {@link SCCKey} for a given plaintext based on the current Secure Crypto Config file.
	 * 
	 * A new {@link SCCKey} can be created with
	 * {@link SCCKey#createKey(org.securecryptoconfig.SCCKey.KeyUseCase)} with
	 * {@link SCCKey.KeyUseCase#SymmetricEncryption}
	 * 
	 * @param key: SCCKey{@link SCCKey}text: as byte[]
	 * @return {@link SCCCiphertext}
	 * @throws CoseException
	 * @throws InvalidKeyException: If {@link SCCKey} has not the
	 *                              {@link KeyType#Symmetric}
	 * @throws SCCException 
	 */
	public AbstractSCCCiphertext encryptSymmetric(AbstractSCCKey key, byte[] plaintext)
			throws CoseException, InvalidKeyException, SCCException;
	
	

	/**
	 * Ciphertext will be first decrypted and then encrypted again with the current
	 * used Secure Crypto Config file.
	 * 
	 * @param key: {@link SCCKey}
	 * @param ciphertext: {@link SCCCiphertext}
	 * @return {@link SCCCiphertext}
	 * @throws CoseException
	 * @throws InvalidKeyException: If {@link SCCKey} has not the
	 *                              {@link KeyType#Symmetric}
	 * @throws SCCException 
	 */
	public AbstractSCCCiphertext reEncryptSymmetric(AbstractSCCKey key, AbstractSCCCiphertext ciphertext)
			throws CoseException, InvalidKeyException, SCCException;
	

	/**
	 * Decryption of a given {@link SCCCiphertext}.
	 * 
	 * @param key: {@link SCCKey}
	 * @param sccciphertext: {@link SCCCiphertext}
	 * @return {@link PlaintextContainer}
	 * @throws CoseException
	 * @throws InvalidKeyException: If {@link SCCKey} has not the
	 *                              {@link KeyType#Symmetric}
	 */
	public PlaintextContainerInterface decryptSymmetric(AbstractSCCKey key, AbstractSCCCiphertext sccciphertext)
			throws CoseException, InvalidKeyException;

	// Asymmetric

	/**
	 * Asymmetric encryption with a certain {@link SCCKey} for a given plaintext based on the current Secure Crypto Config file.
	 * 
	 * A new {@link SCCKey} can be created with
	 * {@link SCCKey#createKey(org.securecryptoconfig.SCCKey.KeyUseCase)} with
	 * {@link SCCKey.KeyUseCase#AsymmetricEncryption}
	 * 
	 * @param key: {@link SCCKey}
	 * @param plaintext: as {@link PlaintextContainer}
	 * @return {@link SCCCiphertext}
	 * @throws CoseException
	 * @throws InvalidKeyException: If {@link SCCKey} has not the
	 *                              {@link KeyType#Asymmetric}
	 * @throws SCCException
	 */
	public AbstractSCCCiphertext encryptAsymmetric(AbstractSCCKey key, PlaintextContainerInterface plaintext)
			throws CoseException, InvalidKeyException, SCCException;

	/**
	 * Asymmetric encryption with a certain {@link SCCKey} for a given plaintext based on the current Secure Crypto Config file.
	 * 
	 * A new {@link SCCKey} can be created with
	 * {@link SCCKey#createKey(org.securecryptoconfig.SCCKey.KeyUseCase)} with
	 * {@link SCCKey.KeyUseCase#AsymmetricEncryption}
	 * 
	 * @param key: {@link SCCKey}
	 * @param plaintext: as byte[]
	 * @return {@link SCCCiphertext}
	 * @throws CoseException
	 * @throws InvalidKeyException: If {@link SCCKey} has not the
	 *                              {@link KeyType#Asymmetric}
	 * @throws SCCException
	 */
	public AbstractSCCCiphertext encryptAsymmetric(AbstractSCCKey key, byte[] plaintext)
			throws CoseException, InvalidKeyException, SCCException;
	


	/**

	 * Ciphertext will be first decrypted and then encrypted based on the current Secure Crypto Config file.
	 * 
	 * @param key: {@link SCCKey}
	 * @param ciphertext: {@link SCCCiphertext}
	 * @return {@link SCCCiphertext}
	 * @throws CoseException
	 * @throws InvalidKeyException: If {@link SCCKey} has not the
	 *                              {@link KeyType#Asymmetric}
	 * @throws SCCException
	 */
	public AbstractSCCCiphertext reEncryptAsymmetric(AbstractSCCKey key, AbstractSCCCiphertext ciphertext)
			throws CoseException, InvalidKeyException, SCCException;

	/**
	 * Asymmetric decryption with a certain {@link SCCKey} for a given
	 * {@link SCCCiphertext}.
	 * 
	 * @param key: {@link SCCKey}
	 * @param ciphertext: {@link SCCCiphertext}
	 * @return {@link PlaintextContainer}
	 * @throws CoseException
	 * @throws InvalidKeyException: If {@link SCCKey} has not the
	 *                              {@link KeyType#Asymmetric}
	 * @throws SCCException
	 */
	public PlaintextContainerInterface decryptAsymmetric(AbstractSCCKey key, AbstractSCCCiphertext ciphertext)
			throws CoseException, InvalidKeyException, SCCException;

	// Hashing

	/**
	 * Hashing of a given plaintext based on the current Secure Crypto Config file.
	 * 
	 * @param plaintext: as {@link PlaintextContainer}
	 * @return {@link SCCHash}
	 * @throws CoseException
	 * @throws SCCException 
	 */
	public AbstractSCCHash hash(PlaintextContainerInterface plaintext) throws CoseException, SCCException;

	/**
	 * Hashing of a given plaintext based on the current Secure Crypto Config file.
	 * 
	 * @param plaintext: as byte[]
	 * @return {@link SCCHash}
	 * @throws CoseException
	 * @throws SCCException 
	 */
	public AbstractSCCHash hash(byte[] plaintext) throws CoseException, SCCException;


	/**
	 * Given a {@link SCCHash} of a plaintext: the corresponding plaintext will be
	 * hashed again with the current Secure Crypto Config.
	 * 
	 * @param plaintext: as {@link PlaintextContainer}
	 * @param hash: {@link SCCHash}
	 * @return {@link SCCHash}
	 * @throws CoseException
	 * @throws SCCException 
	 */
	public AbstractSCCHash updateHash(PlaintextContainerInterface plaintext, AbstractSCCHash hash) throws CoseException, SCCException;


	/**
	 * Given a {@link SCCHash} of a plaintext: the corresponding plaintext will be
	 * hashed again with the current Secure Crypto Config.
	 * 
	 * @param plaintext: as byte[]
	 * @param hash: {@link SCCHash}
	 * @return {@link SCCHash}
	 * @throws CoseException
	 * @throws SCCException 
	 */
	public AbstractSCCHash updateHash(byte[] plaintext, AbstractSCCHash hash) throws CoseException, SCCException;
	

	/**
	 * Validate a given {@link SCCHash} for a specific plaintext.
	 * 
	 * The plaintext will be hashed again and compared if the resulting hash is
	 * identical to the provided one.
	 * 
	 * @param plaintext: as {@link PlaintextContainer}
	 * @param hash: {@link SCCHash}
	 * @return boolean
	 * @throws CoseException
	 * @throws SCCException 
	 */
	public boolean validateHash(PlaintextContainerInterface plaintext, AbstractSCCHash hash) throws CoseException, SCCException;

	/**
	 * Validate a given {@link SCCHash} for a specific plaintext.
	 * 
	 * The plaintext will be hashed again and compared if the resulting hash is
	 * identical to the provided one.
	 * 
	 * @param plaintext: as byte[]
	 * @param hash: {@link SCCHash}
	 * @return boolean
	 * @throws CoseException
	 * @throws SCCException 
	 */
	public boolean validateHash(byte[] plaintext, AbstractSCCHash hash) throws CoseException, SCCException;

	// Digital Signature

	/**
	 * Signing of a plaintext with a specific {@link SCCKey} based on the current Secure Crypto Config file.
	 * 
	 * A new {@link SCCKey} can be created with
	 * {@link SCCKey#createKey(org.securecryptoconfig.SCCKey.KeyUseCase)} with
	 * {@link SCCKey.KeyUseCase#Signing}
	 * 
	 * @param key: {@link SCCKey}
	 * @param plaintext: as {@link PlaintextContainer}
	 * @return {@link SCCSignature}
	 * @throws CoseException
	 * @throws InvalidKeyException: If {@link SCCKey} has not the
	 *                              {@link KeyType#Asymmetric}
	 * @throws SCCException
	 */
	public AbstractSCCSignature sign(AbstractSCCKey key, PlaintextContainerInterface plaintext)
			throws CoseException, InvalidKeyException, SCCException;


	/**
	 * Signing of a plaintext with a specific {@link SCCKey} based on the current Secure Crypto Config file.
	 * 
	 * A new {@link SCCKey} can be created with
	 * {@link SCCKey#createKey(org.securecryptoconfig.SCCKey.KeyUseCase)} with
	 * {@link SCCKey.KeyUseCase#Signing}
	 * 
	 * @param key: {@link SCCKey}
	 * @param plaintext: as byte[]
	 * @return {@link SCCSignature}
	 * @throws CoseException
	 * @throws InvalidKeyException: If {@link SCCKey} has not the
	 *                              {@link KeyType#Asymmetric}
	 * @throws SCCException
	 */
	public AbstractSCCSignature sign(AbstractSCCKey key, byte[] plaintext)
			throws CoseException, InvalidKeyException, SCCException;


	/**
	 * Update the exsting {@link SCCSignature} of a plaintext with a new signature based on the current Secure
	 * Crypto Config.
	 * 
	 * @param key: {@link SCCKey}
	 * @param plaintext: as {@link PlaintextContainer}
	 * @return {@link SCCSignature}
	 * @throws CoseException
	 * @throws InvalidKeyException: If {@link SCCKey} has not the
	 *                              {@link KeyType#Asymmetric}
	 * @throws SCCException
	 */
	public AbstractSCCSignature updateSignature(AbstractSCCKey key, PlaintextContainerInterface plaintext)
			throws CoseException, InvalidKeyException, SCCException;


	/**
	 * Update the exsting {@link SCCSignature} of a plaintext with a new signature based on the current Secure
	 * Crypto Config.
	 * 
	 * @param key: {@link SCCKey}
	 * @param plaintext: as byte[]
	 * @return {@link SCCSignature}
	 * @throws CoseException
	 * @throws InvalidKeyException: If {@link SCCKey} has not the
	 *                              {@link KeyType#Asymmetric}
	 * @throws SCCException
	 */
	public AbstractSCCSignature updateSignature(AbstractSCCKey key, byte[] plaintext)
			throws CoseException, InvalidKeyException, SCCException;
	
	/**
	 * Validate a {@link SCCSignature}.
	 * 
	 * @param key: {@link AbstractSCCKey}
	 * @param signature: {@link SCCSignature}
	 * @return boolean
	 * @throws InvalidKeyException: If {@link SCCKey} has not the
	 *                              {@link KeyType#Asymmetric}
	 * @throws SCCException
	 */
	public boolean validateSignature(AbstractSCCKey key, AbstractSCCSignature signature)
			throws InvalidKeyException, SCCException;

	/**
	 * Validate a {@link SCCSignature}.
	 * 
	 * @param key: {@link AbstractSCCKey}
	 * @param signature: as byte[] representation of {@link SCCSignature}
	 * @return boolean
	 * @throws InvalidKeyException: If {@link SCCKey} has not the
	 *                              {@link KeyType#Asymmetric}
	 * @throws SCCException
	 */
	public boolean validateSignature(AbstractSCCKey key, byte[] signature) throws InvalidKeyException, SCCException;

	// Password Hashing

	/**
	 * Hash a password based on the current Secure Crypto Config file.
	 * 
	 * @param password: as {@link PlaintextContainer}
	 * @return {@link SCCPasswordHash}
	 * @throws CoseException
	 * @throws SCCException 
	 */
	public AbstractSCCPasswordHash passwordHash(PlaintextContainerInterface password) throws CoseException, SCCException;


	/**
	 * Hash a password based on the current Secure Crypto Config file.
	 * 
	 * @param password: as byte[]
	 * @return {@link SCCPasswordHash}
	 * @throws CoseException
	 * @throws SCCException 
	 */
	public AbstractSCCPasswordHash passwordHash(byte[] password) throws CoseException, SCCException;
	

	/**
	 * Validate a given {@link SCCPasswordHash} against given password.
	 * 
	 * The password will be hashed again and compared if resulting hash is identical
	 * to the given one.
	 * 
	 * @param password: as {@link PlaintextContainer}
	 * @param passwordhash: {@link SCCPasswordHash}
	 * @return boolean
	 * @throws CoseException
	 * @throws SCCException 
	 */
	public boolean validatePasswordHash(PlaintextContainerInterface password, AbstractSCCPasswordHash passwordhash)
			throws CoseException, SCCException;

	/**
	 * Validate a given {@link SCCPasswordHash} against given password.
	 * 
	 * The password will be hashed again and compared if resulting hash is identical
	 * to the given one.
	 * 
	 * @param password: as byte[]
	 * @param passwordhash: {@link SCCPasswordHash}
	 * @return boolean
	 * @throws CoseException
	 * @throws SCCException 
	 */
	public boolean validatePasswordHash(byte[] password, AbstractSCCPasswordHash passwordhash) throws CoseException, SCCException;
}

/**
 * Abstract Class for a container representing the plaintext processed in
 * cryptographic use cases.
 * 
 * A PlaintextContainer contains the plaintext as byte[] representation. The
 * class provides various cryptography operations that can be performed on the
 * plaintext (e.g. encryption, signing).
 * 
 */
abstract interface PlaintextContainerInterface {

	/**
	 * Get byte[] representation of {@link PlaintextContainer}
	 * 
	 * @return byte[]
	 */
	abstract byte[] toBytes();

	/**
	 * Get String representation of {@link PlaintextContainer} depending on given
	 * Charset
	 * 
	 * @param c
	 * @return String
	 */
	abstract String toString(Charset c);
	
	/**
	 * Returns String representation of PlaintextContainer.
	 * As charset "UTF-8" is used. To choose another charset call {@link PlaintextContainerInterface#toString(Charset)}
	 * @return String
	 */
	@Override
	public abstract String toString();

	/**
	 * Validate a given {@link SCCHash} against a {@link PlaintextContainer} value.
	 * 
	 * The{@link PlaintextContainer} value will be hashed again and compared if
	 * resulting hash is identical to the given one.
	 * 
	 * @param hash: {@link SCCHash}
	 * @return boolean
	 * @throws SCCException
	 */
	abstract boolean validateHash(AbstractSCCHash hash) throws SCCException;

	/**
	 * Validate a given {@link SCCPasswordHash} against a {@link PlaintextContainer}
	 * value representing the password.
	 * 
	 * The {@link PlaintextContainer} value will be hashed again and compared if
	 * resulting hash is identical to the given one.
	 * 
	 * @param passwordhash: {@link SCCPasswordHash}
	 * @return boolean
	 * @throws SCCException
	 */
	abstract boolean validatePasswordHash(AbstractSCCPasswordHash passwordHash) throws SCCException;

	/**
	 * Symmetric encryption with a certain {@link SCCKey} for
	 * {@link PlaintextContainer} value.
	 * 
	 * A new SCCKey can be created with
	 * {@link SCCKey#createKey(org.securecryptoconfig.SCCKey.KeyUseCase)} with
	 * {@link SCCKey.KeyUseCase#SymmetricEncryption}. Alternatively it is also
	 * possible to derive a key from a password with
	 * {@link SCCKey#createSymmetricKeyWithPassword(byte[])}
	 * 
	 * @param key: {@link SCCKey}
	 * @return {@link SCCCiphertext}
	 * @throws SCCException
	 */
	abstract AbstractSCCCiphertext encryptSymmetric(AbstractSCCKey key) throws SCCException;

	/**
	 * Asymmetric encryption with a certain {@link SCCKey} for
	 * {@link PlaintextContainer} value.
	 * 
	 * A new SCCKey can be created with
	 * {@link SCCKey#createKey(org.securecryptoconfig.SCCKey.KeyUseCase)} with
	 * {@link SCCKey.KeyUseCase#AsymmetricEncryption}
	 * 
	 * @param key: {@link SCCKey}
	 * @return {@link SCCCiphertext}
	 * @throws SCCException
	 */
	abstract AbstractSCCCiphertext encryptAsymmetric(AbstractSCCKey key) throws SCCException;

	/**
	 * Signing of a {@link PlaintextContainer} value with a specific {@link SCCKey}.
	 * 
	 * A new SCCKey can be created with
	 * {@link SCCKey#createKey(org.securecryptoconfig.SCCKey.KeyUseCase)} with
	 * {@link SCCKey.KeyUseCase#Signing}
	 * 
	 * @param key: {@link SCCKey}
	 * @return {@link SCCSignature}
	 * @throws SCCException
	 */
	abstract AbstractSCCSignature sign(AbstractSCCKey key) throws SCCException;

	/**
	 * Hashing of a plaintext ({@link PlaintextContainer}).
	 * 
	 * @return {@link SCCHash}
	 * @throws SCCException
	 */
	abstract AbstractSCCHash hash() throws SCCException;

	/**
	 * Assume the plaintext ({@link PlaintextContainer}) represents a password and
	 * perform password hashing .
	 * 
	 * @return {@link SCCPasswordHash}
	 * @throws SCCException
	 */
	abstract AbstractSCCPasswordHash passwordHash() throws SCCException;

}

/**
 * Abstract Class for a Container for the ciphertext (as result from encrypting
 * a plaintext/plaintextcontainer).
 * 
 * SCCCiphertext contains a byte[] representation of a COSE message. The byte[]
 * contains the encrypted plaintext as well as all the parameters used during
 * encryption. The inclusion of the used parameters, except the key, in the
 * ciphertext ensures that decryption implementation code does not need to know
 * the used algorithm or parameters before decryption, but can parse it from the
 * COSE message. So it only requires the used key.
 *
 */
abstract class AbstractSCCCiphertext {

	byte[] msg;

	public AbstractSCCCiphertext(byte[] msg) {
		this.msg = msg;
	}

	/**
	 * Get byte[] representation of {@link SCCCiphertext}.
	 * 
	 * @return byte[]
	 */
	abstract byte[] toBytes();

	/**
	 * Base64 encode {@link SCCCiphertext}.
	 * 
	 * @return String
	 */
	@Override
	public abstract String toString();

	/**
	 * Symmetric decryption with a certain {@link SCCKey} of {@link SCCCiphertext}.
	 * 
	 * @param key: {@link SCCKey}
	 * @return {@link PlaintextContainer}
	 * @throws SCCException
	 */
	abstract PlaintextContainerInterface decryptSymmetric(AbstractSCCKey key) throws SCCException;

	/**
	 * Asymmetric decryption with a certain {@link SCCKey} of {@link SCCCiphertext}.
	 * 
	 * @param key: {@link SCCKey}
	 * @return {@link PlaintextContainer}
	 * @throws SCCException
	 */
	abstract PlaintextContainerInterface decryptAsymmetric(AbstractSCCKey key) throws SCCException;

	/**
	 * Encrypts {@link SCCCiphertext} again, possibly using a different
	 * algorithm/parameters.
	 * 
	 * The ciphertext will be first decrypted and then encrypted again with the
	 * current used Secure Crypto Config file.
	 * 
	 * @param key: {@link SCCKey}
	 * @return {@link SCCCiphertext}
	 * @throws SCCException
	 */
	abstract AbstractSCCCiphertext reEncryptSymmetric(AbstractSCCKey key) throws SCCException;

	/**
	 * Encrypts {@link SCCCiphertext} again, possibly using a different
	 * algorithm/parameters.
	 * 
	 * The ciphertext will be first decrypted and then encrypted again with the
	 * current used Secure Crypto Config file.
	 * 
	 * @param key: {@link SCCKey}
	 * @return {@link SCCCiphertext}
	 * @throws SCCException
	 */
	abstract AbstractSCCCiphertext reEncryptAsymmetric(AbstractSCCKey key) throws SCCException;

}

/**
 * Abstract Class for the Container of a key used for cryptography
 * operations like symmetric or asymmetric encryption.
 * 
 * SCCKey contains a byte[] representation of a key as well as all the
 * parameters needed to define the type and use case of the key.
 *
 */
abstract class AbstractSCCKey {

	KeyType type;
	byte[] privateKey, publicKey;
	String algorithm;

	protected AbstractSCCKey(KeyType type, byte[] publicKey, byte[] privateKey, String algorithm) {
		this.type = type;
		this.publicKey = publicKey;
		this.privateKey = privateKey;
		this.algorithm = algorithm;

	}


	/**
	 * Get byte[] representation of {@link SCCKey}.
	 * 
	 * @return byte[]: returns byte[] representation of key in case that the key has
	 *         {@link SCCKey.KeyType#Symmetric}
	 * @throws InvalidKeyException 
	 */
	abstract byte[] toBytes() throws InvalidKeyException;

	/**
	 * Get byte[] representation of public key.
	 * 
	 * @return byte[]: returns byte[] representation of public key in case that the
	 *         key has {@link SCCKey.KeyType#Asymmetric}
	 * @throws InvalidKeyException 
	 */
	abstract byte[] getPublicKeyBytes() throws InvalidKeyException;

	/**
	 * Get byte[] representation of private key.
	 * 
	 * @return byte[]: returns byte[] representation of private key in case that the
	 *         key has {@link SCCKey.KeyType#Asymmetric}
	 * @throws InvalidKeyException 
	 */
	abstract byte[] getPrivateKeyBytes() throws InvalidKeyException;

	/**
	 * Get {@link KeyType} of {@link SCCKey}.
	 * 
	 * A key can either be {@link SCCKey.KeyType#Symmetric} {@link Or}
	 * {@link SCCKey.KeyType#Asymmetric}. According to its type a key can be used
	 * for different cryptographic use cases.
	 * 
	 * @return {@link KeyType}
	 */
	abstract KeyType getKeyType();

	/**
	 * Returns the algorithm used for key generation.
	 * 
	 * @return String: algorithm used for key generation
	 */
	abstract String getAlgorithm();

}

/**
 * Abstract Class for a Container for a Cryptographic Hash.
 * 
 * SCCHash contains a byte[] representation of a COSE message. The byte[]
 * contains the hash as well as all the parameters used during hashing. The
 * inclusion of the used parameters in the hash ensures that validation
 * implementation code does not need to know the used algorithm or parameters
 * before validation, but can parse it from the COSE message.
 *
 */
abstract class AbstractSCCHash {

	byte[] hashMsg;

	/**
	 * Constructor that creates a new SCCHash object based on existing COSE message.
	 * 
	 * @param hashMsg: byte[] of COSE message
	 */
	public AbstractSCCHash(byte[] hashMsg) {
		this.hashMsg = hashMsg;
	}

	/**
	 * Constructor that creates a new SCCHash object based on existing COSE message.
	 * 
	 * @param hashMsg: Base64 encoded String of COSE message
	 */
	public AbstractSCCHash(String hash) {
		this(Base64.getDecoder().decode(hash));
	}

	/**
	 * Get byte[] representation of {@link SCCHash}.
	 * 
	 * @return byte[]
	 */
	abstract byte[] toBytes();

	/**
	 * Base64 encode {@link SCCHash}.
	 * 
	 * @return String
	 */
	@Override
	public abstract String toString();

	/**
	 * Validate if a {@link SCCHash} matches hash of given plaintext.
	 * 
	 * The plaintext will be hashed again and compared if resulting hash is
	 * identical to the given one.
	 * 
	 * @param plaintext: as {@link PlaintextContainer}
	 * @return boolean
	 * @throws SCCException
	 */
	abstract boolean validateHash(PlaintextContainerInterface plaintext) throws SCCException;

	/**
	 * Validate if a {@link SCCHash} matches hash of given plaintext.
	 * 
	 * The plaintext will be hashed again and compared if resulting hash is
	 * identical to the given one.
	 * 
	 * @param plaintext: as byte[]
	 * @return boolean
	 * @throws SCCException
	 */
	abstract boolean validateHash(byte[] plaintext) throws SCCException;

	/**
	 * {@link SCCHash} of a plaintext.
	 * 
	 * The corresponding plaintext will be hashed again with the current Secure
	 * Crypto Config.
	 * 
	 * @param plaintext: as {@link PlaintextContainer}
	 * @return {@link SCCHash}
	 * @throws SCCException
	 */
	abstract AbstractSCCHash updateHash(PlaintextContainerInterface plaintext) throws SCCException;

	/**
	 * {@link SCCHash} of a plaintext.
	 * 
	 * The corresponding plaintext will be hashed again with the current Secure
	 * Crypto Config.
	 * 
	 * @param plaintext: as byte[]
	 * @return {@link SCCHash}
	 * @throws SCCException
	 */
	abstract AbstractSCCHash updateHash(byte[] plaintext) throws SCCException;

}

/**
 * Abstract Class for a Container for a Cryptographic Password Hash.
 * 
 * SCCHash contains a byte[] representation of a COSE message. The byte[]
 * contains the password hash as well as all the parameters used during hashing.
 * The inclusion of the used parameters in the password hash ensures that
 * validation implementation code does not need to know the used algorithm or
 * parameters before validation, but can parse it from the COSE message.
 *
 */
abstract class AbstractSCCPasswordHash {

	byte[] hashMsg;

	/**
	 * Constructor that creates a new AbstractSCCPasswordHash object based on
	 * existing COSE message.
	 * 
	 * @param hashMsg: byte[] of COSE message
	 */
	public AbstractSCCPasswordHash(byte[] hashMsg) {
		this.hashMsg = hashMsg;
	}

	/**
	 * Constructor that creates a new AbstractSCCPasswordHash object based on
	 * existing COSE message.
	 * 
	 * @param hashMsg: Base64 encoded String of COSE message
	 */
	public AbstractSCCPasswordHash(String hash) {
		this(Base64.getDecoder().decode(hash));
	}

	/**
	 * Get byte[] representation of {@link SCCPasswordHash}.
	 * 
	 * @return byte[]
	 */
	abstract byte[] toBytes();

	/**
	 * Base64 encode {@link SCCPasswordHash}.
	 * 
	 * @return String
	 */
	@Override
	public abstract String toString();

	/**
	 * Validate if {@link SCCPasswordHash} matches hash of a given password.
	 * 
	 * The password will be hashed again and compared if resulting hash is identical
	 * to the given one.
	 * 
	 * @param password: as {@link PlaintextContainer}
	 * @return boolean
	 * @throws SCCException
	 */
	abstract boolean validatePasswordHash(PlaintextContainerInterface password) throws SCCException;

	/**
	 * Validate if {@link SCCPasswordHash} matches hash of a given password.
	 * 
	 * The password will be hashed again and compared if resulting hash is identical
	 * to the given one.
	 * 
	 * @param password: as byte[]
	 * @return boolean
	 * @throws SCCException
	 */
	abstract boolean validatePasswordHash(byte[] password) throws SCCException;

}

/**
 * Abstract class for a Container for a Digital Signature.
 * 
 * SCCSignature contains a byte[] representation of a COSE message. The byte[]
 * contains the signature as well as all the parameters used during signing. The
 * inclusion of the used parameters in the signature ensures that validation
 * implementation code does not need to know the used algorithm or parameters
 * before validation, but can parse it from the COSE message.
 *
 */
abstract class AbstractSCCSignature {
	byte[] signatureMsg;

	public AbstractSCCSignature(byte[] signatureMasg) {
		this.signatureMsg = signatureMasg;
	}

	/**
	 * Constructor that creates a new AbstractSCCSignature object based on existing
	 * COSE message.
	 * 
	 * @param hashMsg: Base64 encoded String of COSE message
	 */
	public AbstractSCCSignature(String hash) {
		this(Base64.getDecoder().decode(hash));
	}

	/**
	 * Get byte[] representation of {@link SCCSignature}.
	 * 
	 * @return byte[]
	 */
	abstract byte[] toBytes();

	/**
	 * Base64 encode {@link AbstractSCCSignature}.
	 * 
	 * @return String
	 */
	@Override
	public abstract String toString();

	/**
	 * Validate {@link SCCSignature}.
	 * 
	 * @param key: {@link AbstractSCCKey}
	 * @return boolean
	 * @throws SCCException
	 */
	abstract boolean validateSignature(AbstractSCCKey key) throws SCCException;

	/**
	 * Update signature possibly using a different algorithm/parameters.
	 * 
	 * The corresponding plaintext will be signed again with the current Secure
	 * Crypto Config.
	 * 
	 * @param key: {@link SCCKey}
	 * @param plaintext: as {@link PlaintextContainer}
	 * @return {@link SCCSignature}
	 * @throws SCCException
	 */
	abstract AbstractSCCSignature updateSignature(PlaintextContainerInterface plaintext, AbstractSCCKey key)
			throws SCCException;

}
