package main;

import java.nio.charset.Charset;
import COSE.CoseException;
import main.SCCKey.KeyType;

abstract interface SecureCryptoConfigInterface {

	// Symmetric Encryption
	
	/**
	 * Symmetric encryption with a certain {@link SCCKey} for a given plaintext.
	 * A new SCCKey can be created with {@link SCCKey#createKey(main.SCCKey.KeyUseCase)} with {@link SCCKey.KeyUseCase#SymmetricEncryption}
	 * Alternatively it is also possible to create a key derived from a password with {@link SCCKey#createSymmetricKeyWithPassword(byte[])}
	 * @param key: {@link SCCKey} 
	 * @param plaintext: as {@link PlaintextContainer}
	 * @return {@link SCCCiphertext}
	 * @throws CoseException
	 */
	public AbstractSCCCiphertext encryptSymmetric(AbstractSCCKey key, PlaintextContainerInterface plaintext)
			throws CoseException;
	
	/**
	 * Symmetric encryption with a certain {@link SCCKey} for a given plaintext.
	 * A new SCCKey can be created with {@link SCCKey#createKey(main.SCCKey.KeyUseCase)} with {@link SCCKey.KeyUseCase#SymmetricEncryption}
	 * @param key: SCCKey{@link SCCKey}text: as byte[]
	 * @return {@link SCCCiphertext}
	 * @throws CoseException
	 */
	public AbstractSCCCiphertext encryptSymmetric(AbstractSCCKey key, byte[] plaintext) throws CoseException;

	/**
	 * ReEncrypts a given {@link SCCCiphertext}. Ciphertext will be first decrypted and then
	 * encrypted again with the current used Secure Crypto Config file.
	 * @param key: {@link SCCKey} 
	 * @param ciphertext: {@link SCCCiphertext}
	 * @return {@link SCCCiphertext}
	 * @throws CoseException
	 */
	public AbstractSCCCiphertext reEncryptSymmetric(AbstractSCCKey key, AbstractSCCCiphertext ciphertext)
			throws CoseException;

	/**
	 * Decryption of a given {@link SCCCiphertext}.
	 * @param key: {@link SCCKey} 
	 * @param sccciphertext: {@link SCCCiphertext}
	 * @return {@link PlaintextContainer}
	 * @throws CoseException
	 */
	public PlaintextContainerInterface decryptSymmetric(AbstractSCCKey key, AbstractSCCCiphertext sccciphertext)
			throws CoseException;

	// Asymmetric
	
	/**
	 * Asymmetric encryption with a certain {@link SCCKey} for a given plaintext.
	 * A new SCCKey can be created with {@link SCCKey#createKey(main.SCCKey.KeyUseCase)} with {@link SCCKey.KeyUseCase#AsymmetricEncryption}
	 * @param keyPair: {@link SCCKey}
	 * @param plaintext: as {@link PlaintextContainer}
	 * @return {@link SCCCiphertext}
	 * @throws CoseException
	 */
	public AbstractSCCCiphertext encryptAsymmetric(AbstractSCCKey keyPair, PlaintextContainerInterface plaintext)
			throws CoseException;

	/**
	 * Asymmetric encryption with a certain {@link SCCKey} for a given plaintext.
	 * A new SCCKey can be created with {@link SCCKey#createKey(main.SCCKey.KeyUseCase)} with {@link SCCKey.KeyUseCase#AsymmetricEncryption}
	 * @param keyPair: {@link SCCKey}
	 * @param plaintext: as byte[]
	 * @return {@link SCCCiphertext}
	 * @throws CoseException
	 */
	public AbstractSCCCiphertext encryptAsymmetric(AbstractSCCKey keyPair, byte[] plaintext) throws CoseException;

	/**
	 * ReEncrypts a given {@link SCCCiphertext}. Ciphertext will be first decrypted and then
	 * encrypted with the current Secure Crypto Config again.
	 * @param keyPair: {@link SCCKey}
	 * @param ciphertext: {@link SCCCiphertext}
	 * @return {@link SCCCiphertext}
	 * @throws CoseException
	 */
	public AbstractSCCCiphertext reEncryptAsymmetric(AbstractSCCKey keyPair, AbstractSCCCiphertext ciphertext)
			throws CoseException;

	/**
	 * Asymmetric decryption with a certain {@link SCCKey} for a given {@link SCCCiphertext}.
	 * @param keyPair: {@link SCCKey}
	 * @param ciphertext: {@link SCCCiphertext}
	 * @return {@link PlaintextContainer}
	 * @throws CoseException
	 */
	public PlaintextContainerInterface decryptAsymmetric(AbstractSCCKey keyPair, AbstractSCCCiphertext ciphertext)
			throws CoseException;

	// Hashing
	
	/**
	 * Hashing of a given plaintext
	 * @param plaintext: as {@link PlaintextContainer}
	 * @return {@link SCCHash}
	 * @throws CoseException
	 */
	public AbstractSCCHash hash(PlaintextContainerInterface plaintext) throws CoseException;

	/**
	 * Hashing of a given plaintext
	 * @param plaintext: as byte[]
	 * @return {@link SCCHash}
	 * @throws CoseException
	 */
	public AbstractSCCHash hash(byte[] plaintext) throws CoseException;

	/**
	 * Given a {@link SCCHash} of a plaintext: the corresponding plaintext will be hashed again
	 * with the current Secure Crypto Config.
	 * @param plaintext: as {@link PlaintextContainer}
	 * @param hash: {@link SCCHash}
	 * @return {@link SCCHash}
	 * @throws CoseException
	 */
	public AbstractSCCHash updateHash(PlaintextContainerInterface plaintext, AbstractSCCHash hash) throws CoseException;

	/**
	 * Given a {@link SCCHash} of a plaintext: the corresponding plaintext will be hashed again
	 * with the current Secure Crypto Config.
	 * @param plaintext: as byte[]
	 * @param hash: {@link SCCHash}
	 * @return {@link SCCHash}
	 * @throws CoseException
	 */
	public AbstractSCCHash updateHash(byte[] plaintext, AbstractSCCHash hash) throws CoseException;

	/**
	 * Look if a given {@link SCCHash} for a specific plaintext is valid: plaintext will be hashed again and 
	 * compared if resulting hash is identical to the given one.
	 * @param plaintext: as {@link PlaintextContainer}
	 * @param hash: {@link SCCHash}
	 * @return boolean
	 * @throws CoseException
	 */
	public boolean validateHash(PlaintextContainerInterface plaintext, AbstractSCCHash hash) throws CoseException;

	/**
	 * Look if a given {@link SCCHash} for a specific plaintext is valid: plaintext will be hashed again and 
	 * compared if resulting hash is identical to the given one.
	 * @param plaintext: as byte[]
	 * @param hash: {@link SCCHash}
	 * @return boolean
	 * @throws CoseException
	 */
	public boolean validateHash(byte[] plaintext, AbstractSCCHash hash) throws CoseException;

	// Digital Signature
	
	/**
	 * Signing of a plaintext with a specific {@link SCCKey}.
	 * A new SCCKey can be created with {@link SCCKey#createKey(main.SCCKey.KeyUseCase)} with {@link SCCKey.KeyUseCase#Signing}
	 * @param keyPair: {@link SCCKey}
	 * @param plaintext: as {@link PlaintextContainer}
	 * @return {@link SCCSignature}
	 * @throws CoseException
	 */
	public AbstractSCCSignature sign(AbstractSCCKey keyPair, PlaintextContainerInterface plaintext)
			throws CoseException;

	/**
	 * Signing of a plaintext with a specific {@link SCCKey}.
	 * A new SCCKey can be created with {@link SCCKey#createKey(main.SCCKey.KeyUseCase)} with {@link SCCKey.KeyUseCase#Signing}
	 * @param keyPair: {@link SCCKey}
	 * @param plaintext: as byte[]
	 * @return {@link SCCSignature}
	 * @throws CoseException
	 */
	public AbstractSCCSignature sign(AbstractSCCKey keyPair, byte[] plaintext) throws CoseException;

	/**
	 * Given a {@link SCCSignature} of a plaintext: the corresponding plaintext will be signed
	 * again with the current Secure Crypto Config.
	 * @param keyPair: {@link SCCKey}
	 * @param plaintext: as {@link PlaintextContainer}
	 * @return {@link SCCSignature}
	 * @throws CoseException
	 */
	public AbstractSCCSignature updateSignature(AbstractSCCKey keyPair, PlaintextContainerInterface plaintext)
			throws CoseException;
	
	/**
	 * Given a {@link SCCSignature} of a plaintext: the corresponding plaintext will be signed
	 * again with the current Secure Crypto Config.
	 * @param keyPair: {@link SCCKey}
	 * @param plaintext: as byte[]
	 * @return {@link SCCSignature}
	 * @throws CoseException
	 */
	public AbstractSCCSignature updateSignature(AbstractSCCKey keyPair, byte[] plaintext)
			throws CoseException;
	
	/**
	 * A given {@link SCCSignature} is checked for validity
	 * @param keyPair: {@link AbstractSCCKey}
	 * @param signature: {@link SCCSignature}
	 * @return boolean
	 */
	public boolean validateSignature(AbstractSCCKey keyPair, AbstractSCCSignature signature);
	
	/**
	 * A given {@link SCCSignature} is checked for validity
	 * @param keyPair: {@link AbstractSCCKey}
	 * @param signature: as byte[] representation of {@link SCCSignature}
	 * @return boolean
	 */
	public boolean validateSignature(AbstractSCCKey keyPair, byte[] signature);

	// Password Hashing
	
	/**
	 * Given password will be hashed.
	 * @param password: as {@link PlaintextContainer}
	 * @return {@link SCCPasswordHash}
	 * @throws CoseException
	 */
	public AbstractSCCPasswordHash passwordHash(PlaintextContainerInterface password) throws CoseException;

	/**
	 * Given password will be hashed.
	 * @param password: as byte[]
	 * @return {@link SCCPasswordHash}
	 * @throws CoseException
	 */
	public AbstractSCCPasswordHash passwordHash(byte[] password) throws CoseException;

	/**
	 * Look if a given {@link SCCPasswordHash} for a specific plaintext is valid: plaintext will be hashed again and 
	 * compared if resulting hash is identical to the given one.
	 * @param password: as {@link PlaintextContainer}
	 * @param passwordhash: {@link SCCPasswordHash}
	 * @return boolean
	 * @throws CoseException
	 */
	public boolean validatePasswordHash(PlaintextContainerInterface password, AbstractSCCPasswordHash passwordhash)
			throws CoseException;

	/**
	 * Look if a given {@link SCCPasswordHash} for a specific plaintext is valid: plaintext will be hashed again and 
	 * compared if resulting hash is identical to the given one.
	 * @param password: as byte[]
	 * @param passwordhash: {@link SCCPasswordHash}
	 * @return boolean
	 * @throws CoseException
	 */
	public boolean validatePasswordHash(byte[] password, AbstractSCCPasswordHash passwordhash)
			throws CoseException;
}

abstract interface PlaintextContainerInterface {

	/**
	 * Get byte[] representation of {@link PlaintextContainer}
	 * @return byte[]
	 */
	abstract byte[] toBytes();

	/**
	 * Get String representation of {@link PlaintextContainer} depending on given Charset
	 * @param c
	 * @return String
	 */
	abstract String toString(Charset c);


	/**
	 * Look if a given {@link SCCHash} for a {@link PlaintextContainer} value is valid: {@link PlaintextContainer} value will be hashed again and 
	 * compared if resulting hash is identical to the given one.
	 * @param hash: {@link SCCHash}
	 * @return boolean
	 */
	abstract boolean validateHash(AbstractSCCHash hash);

	/**
	 * Look if a given {@link SCCPasswordHash} for a {@link PlaintextContainer} value is valid: {@link PlaintextContainer} value will be hashed again and 
	 * compared if resulting hash is identical to the given one.
	 * @param passwordhash: {@link SCCPasswordHash}
	 * @return boolean
	 */
	abstract boolean validatePasswordHash(AbstractSCCPasswordHash passwordHash);

	/**
	 * Symmetric encryption with a certain {@link SCCKey} for {@link PlaintextContainer} value.
	 * A new SCCKey can be created with {@link SCCKey#createKey(main.SCCKey.KeyUseCase)} with {@link SCCKey.KeyUseCase#SymmetricEncryption}
	 * Alternatively it is also possible to create a key derived from a password with {@link SCCKey#createSymmetricKeyWithPassword(byte[])}
	 * @param key: {@link SCCKey} 
	 * @return {@link SCCCiphertext}
	 */
	abstract AbstractSCCCiphertext encryptSymmetric(AbstractSCCKey key);

	/**
	 * Asymmetric encryption with a certain {@link SCCKey} for {@link PlaintextContainer} value.
	 * A new SCCKey can be created with {@link SCCKey#createKey(main.SCCKey.KeyUseCase)} with {@link SCCKey.KeyUseCase#AsymmetricEncryption}
	 * @param pair: {@link SCCKey}
	 * @return {@link SCCCiphertext}
	 */
	abstract AbstractSCCCiphertext encryptAsymmetric(AbstractSCCKey pair);

	/**
	 * Signing of a {@link PlaintextContainer} value with a specific {@link SCCKey}.
	 * A new SCCKey can be created with {@link SCCKey#createKey(main.SCCKey.KeyUseCase)} with {@link SCCKey.KeyUseCase#Signing}
	 * @param keyPair: {@link SCCKey}
	 * @return {@link SCCSignature}
	 */
	abstract AbstractSCCSignature sign(AbstractSCCKey keyPair);

	/**
	 * Hashing of value from {@link PlaintextContainer}
	 * @return {@link SCCHash}
	 */
	abstract AbstractSCCHash hash();

	/**
	 * Value of {@link PlaintextContainer} will be hashed.
	 * @return {@link SCCPasswordHash}
	 */
	abstract AbstractSCCPasswordHash passwordHash();

}

abstract class AbstractSCCCiphertext {
	
	byte[] msg;

	public AbstractSCCCiphertext(byte[] msg) {
		this.msg = msg;
	}

	/**
	 * Get byte[] representation of {@link SCCCiphertext}
	 * @return byte[]
	 */
	abstract byte[] toBytes();

	/**
	 * Get String representation of {@link SCCCiphertext} depending on given Charset
	 * @param c: Charset
	 * @return String
	 */
	abstract String toString(Charset c);

	/**
	 * Symmetric decryption with a certain {@link SCCKey} of {@link SCCCiphertext}.
	 * @param key: {@link SCCKey}
	 * @return {@link PlaintextContainer}
	 */
	abstract PlaintextContainerInterface decryptSymmetric(AbstractSCCKey key);

	/**
	 *  Asymmetric decryption with a certain {@link SCCKey} of {@link SCCCiphertext}.
	 * @param keyPair: {@link SCCKey} 
	 * @return {@link PlaintextContainer}
	 */
	abstract PlaintextContainerInterface decryptAsymmetric(AbstractSCCKey keyPair);

	/**
	 * ReEncrypts {@link SCCCiphertext}. Ciphertext will be first decrypted and then
	 * encrypted again with the current used Secure Crypto Config file.
	 * @param key: {@link SCCKey} 
	 * @return {@link SCCCiphertext}
	 */
	abstract AbstractSCCCiphertext reEncryptSymmetric(AbstractSCCKey key);

	/**
	 * ReEncrypts {@link SCCCiphertext}. Ciphertext will be first decrypted and then
	 * encrypted with the current Secure Crypto Config again.
	 * @param keyPair: {@link SCCKey}
	 * @return {@link SCCCiphertext}
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
	 * Get byte[] representation of {@link SCCKey}
	 * @return byte[]: returns byte[] representation of key in case that the key has {@link SCCKey.KeyType#Symmetric}
	 */
	abstract byte[] toBytes();
	
	/**
	 * Get byte[] representation of public key
	 * @return byte[]: returns byte[] representation of public key in case that the key has {@link SCCKey.KeyType#Asymmetric}
	 */
	abstract byte[] getPublicKeyBytes();
	
	/**
	 * Get byte[] representation of private key
	 * @return byte[]: returns byte[] representation of private key in case that the key has {@link SCCKey.KeyType#Asymmetric}
	 */
	abstract byte[] getPrivateKeyBytes();
	
	/**
	 * Returns the algorithm used for key generation
	 * @return String: algorithm used for key generation
	 */
	abstract String getAlgorithm();

}

abstract class AbstractSCCHash {

	byte[] hashMsg;

	public AbstractSCCHash(byte[] hashMsg) {
		this.hashMsg = hashMsg;
	}

	/**
	 * Get byte[] representation of {@link SCCHash}
	 * @return byte[]
	 */
	abstract byte[] toBytes();
	
	/**
	 * Get String representation of {@link SCCHash} depending on given Charset
	 * @param c: Charset
	 * @return byte[]
	 */
	abstract String toString(Charset c);
	
	/**
	 * Look if  {@link SCCHash} for a specific plaintext is valid: plaintext will be hashed again and 
	 * compared if resulting hash is identical to the given one.
	 * @param plaintext: as {@link PlaintextContainer}
	 * @return boolean
	 */
	abstract boolean validateHash(PlaintextContainerInterface plaintext);
	
	/**
	 * Look if  {@link SCCHash} for a specific plaintext is valid: plaintext will be hashed again and 
	 * compared if resulting hash is identical to the given one.
	 * @param plaintext: as byte[]
	 * @return boolean
	 */
	abstract boolean validateHash(byte[] plaintext);

	/**
	 * {@link SCCHash} of a plaintext: the corresponding plaintext will be hashed again
	 * with the current Secure Crypto Config.
	 * @param plaintext: as {@link PlaintextContainer}
	 * @return {@link SCCHash}
	 */
	abstract AbstractSCCHash updateHash(PlaintextContainerInterface plaintext);
	
	/**
	 * {@link SCCHash} of a plaintext: the corresponding plaintext will be hashed again
	 * with the current Secure Crypto Config.
	 * @param plaintext: as byte[]
	 * @return {@link SCCHash}
	 */
	abstract AbstractSCCHash updateHash(byte[] plaintext);
	

}

abstract class AbstractSCCPasswordHash {

	byte[] hashMsg;
	

	public AbstractSCCPasswordHash(byte[] hashMsg) {
		this.hashMsg = hashMsg;
	}

	/**
	 * Get byte[] representation of {@link SCCPasswordHash}
	 * @return byte[]
	 */
	abstract byte[] toBytes();
	
	/**
	 * Get String representation of {@link SCCPasswordHash} depending on given Charset
	 * @param c: Charset
	 * @return String
	 */
	abstract String toString(Charset c);
	
	/**
	 * Look {@link SCCPasswordHash} for a specific plaintext is valid: plaintext will be hashed again and 
	 * compared if resulting hash is identical to the given one.
	 * @param password: as {@link PlaintextContainer}
	 * @return boolean
	 */
	abstract boolean validatePasswordHash(PlaintextContainerInterface password);
	
	/**
	 * Look {@link SCCPasswordHash} for a specific plaintext is valid: plaintext will be hashed again and 
	 * compared if resulting hash is identical to the given one.
	 * @param password: as byte[]
	 * @return boolean
	 */
	abstract boolean validatePasswordHash(byte[] password);

}

abstract class AbstractSCCSignature {
	byte[] signatureMsg;

	public AbstractSCCSignature(byte[] signatureMasg) {
		this.signatureMsg = signatureMasg;
	}

	/**
	 * Get byte[] representation of {@link SCCSignature}
	 * @return byte[]
	 */
	abstract byte[] toBytes();

	/**
	 * Get String representation of {@link SCCSignature} depending on given Charset
	 * @param c: Charset
	 * @return String
	 */
	abstract String toString(Charset c);

	/**
	 * {@link SCCSignature} is checked for validity
	 * @param keyPair: {@link AbstractSCCKey}
	 * @return boolean
	 */
	abstract boolean validateSignature(AbstractSCCKey keyPair);

	/**
	 * Given a {@link SCCSignature} of a plaintext: the corresponding plaintext will be signed
	 * again with the current Secure Crypto Config.
	 * @param keyPair: {@link SCCKey}
	 * @param plaintext: as {@link PlaintextContainer}
	 * @return {@link SCCSignature}
	 */
	abstract AbstractSCCSignature updateSignature(PlaintextContainerInterface plaintext, AbstractSCCKey keyPair);

}


