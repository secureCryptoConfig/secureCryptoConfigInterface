package org.securecryptoconfig;

import java.nio.charset.Charset;
import org.securecryptoconfig.SCCKey.KeyType;
import org.securecryptoconfig.SCCKey.KeyUseCase;


/**
 * Interface defining methods that can be used to perform different
 * cryptographic use cases.
 * 
 * Most methods are defined inside {@link SecureCryptoConfig}. To start
 * performing the desired use case make use of this class as starting point of
 * your implementation.
 * 
 * @author Lisa
 *
 */
public abstract interface SecureCryptoConfigInterface {

	// Symmetric Encryption

	/**
	 * Symmetric encryption with a certain {@link SCCKey} for a given plaintext
	 * based on the current Secure Crypto Config file.
	 * 
	 * <br> The encryption can be done as follows:
	 * <pre>
	 * {@code
	 * 	SecureCryptoConfig scc = new SecureCryptoConfig();
	 *  SCCCiphertext c = scc.encryptSymmetric(sccKey, plaintext);
	 * }
	 * </pre>
	 * 
	 * <br>A new {@link SCCKey} for performing can be created with
	 * {@link SCCKey#createKey(KeyUseCase)} as follows:
	 * 
	 * <pre>
	 * {@code
	 * 	SCCKey key = SCCKey.createKey(KeyUseCase.SymmetricEncryption);
	 * }
	 * </pre>
	 * 
	 * Alternatively it is also possible to create a key derived from a password
	 * with {@link SCCKey#createSymmetricKeyWithPassword(byte[])}:
	 * 
	 * <pre>
	 * {@code
	 * 	SCCKey key = SCCKey.createSymmetricKeyWithPassword(password);
	 * }
	 * </pre>
	 * 
	 * Also it is possible to create a SCCKey from already existing SCCKey byte[]
	 * with {@link SCCKey#createFromExistingKey(byte[])}::
	 * 
	 * <pre>
	 * {@code
	 * SCCKey key = SCCKey.createFromExistingKey(existingSCCKey)
	 * }
	 * </pre>
	 * 
	 * A PlaintextContainer representation can be done by calling
	 * {@link PlaintextContainer#PlaintextContainer(byte[])} with the byte[]
	 * representation of the plaintext to be encrypted.
	 * 
	 * 
	 * @param key:       {@link SCCKey}
	 * @param plaintext: as {@link PlaintextContainer}
	 * @return {@link SCCCiphertext}
	 * @throws SCCException 
	 */
	public AbstractSCCCiphertext encryptSymmetric(AbstractSCCKey key, PlaintextContainerInterface plaintext)
			throws SCCException;

	/**
	 * Symmetric encryption with a certain {@link SCCKey} for a given plaintext
	 * based on the current Secure Crypto Config file.
	 * 
	 * <br> The encryption can be done as follows:
	 * <pre>
	 * {@code
	 * 	SecureCryptoConfig scc = new SecureCryptoConfig();
	 *  SCCCiphertext c = scc.encryptSymmetric(sccKey, plaintext);
	 * }
	 * </pre>
	 * 
	 * <br>A new {@link SCCKey} for performing can be created with
	 * {@link SCCKey#createKey(KeyUseCase)} as follows:
	 * 
	 * <pre>
	 * {@code
	 * 	SCCKey key = SCCKey.createKey(KeyUseCase.SymmetricEncryption);
	 * }
	 * </pre>
	 * 
	 * Alternatively it is also possible to create a key derived from a password
	 * with {@link SCCKey#createSymmetricKeyWithPassword(byte[])}:
	 * 
	 * <pre>
	 * {@code
	 * 	SCCKey key = SCCKey.createSymmetricKeyWithPassword(password);
	 * }
	 * </pre>
	 * 
	 * Also it is possible to create a SCCKey from already existing SCCKey byte[]
	 * with {@link SCCKey#createFromExistingKey(byte[])}::
	 * 
	 * <pre>
	 * {@code
	 * SCCKey key = SCCKey.createFromExistingKey(existingSCCKey)
	 * }
	 * </pre>
	 * 
	 * @param key:       {@link SCCKey}
	 * @param plaintext: as byte[]
	 * @return {@link SCCCiphertext}
	 * @throws SCCException
	 */
	public AbstractSCCCiphertext encryptSymmetric(AbstractSCCKey key, byte[] plaintext)
			throws SCCException;

	/**
	 * Ciphertext will be first decrypted and then encrypted again with the current
	 * used Secure Crypto Config file.
	 * 
	 * @param key:        {@link SCCKey}
	 * @param ciphertext: {@link SCCCiphertext}
	 * @return {@link SCCCiphertext}
	 * @throws SCCException
	 */
	public AbstractSCCCiphertext reEncryptSymmetric(AbstractSCCKey key, AbstractSCCCiphertext ciphertext)
			throws SCCException;

	/**
	 * Decryption of a given {@link SCCCiphertext}.
	 * 
	 * @param key:           {@link SCCKey}
	 * @param sccciphertext: {@link SCCCiphertext}
	 * @return {@link PlaintextContainer}
	 * @throws SCCException
	 */
	public PlaintextContainerInterface decryptSymmetric(AbstractSCCKey key, AbstractSCCCiphertext sccciphertext)
			throws SCCException;

	// Asymmetric

	/**
	 * Asymmetric encryption with a certain {@link SCCKey} for a given plaintext
	 * based on the current Secure Crypto Config file.
	 * 
	 * <br> The encryption can be done as follows:
	 * <pre>
	 * {@code
	 * 	SecureCryptoConfig scc = new SecureCryptoConfig();
	 *  SCCCiphertext c = scc.encryptAsymmetric(sccKey, plaintext);
	 * }
	 * </pre>
	 * <br>A new {@link SCCKey} for performing can be created with
	 * {@link SCCKey#createKey(KeyUseCase)} as follows:
	 * 
	 * <pre>
	 * {@code
	 * 	SCCKey key = SCCKey.createKey(KeyUseCase.AsymmetricEncryption);
	 * }
	 * </pre>
	 * 
	 * Also it is possible to create a SCCKey from already existing SCCKey byte[]
	 * with {@link SCCKey#createFromExistingKey(byte[])}::
	 * 
	 * <pre>
	 * {@code
	 * SCCKey key = SCCKey.createFromExistingKey(existingSCCKey)
	 * }
	 * </pre>
	 * 
	 * A PlaintextContainer representation can be done by calling
	 * {@link PlaintextContainer#PlaintextContainer(byte[])} with the byte[]
	 * representation of the plaintext to be encrypted.
	 * 
	 * @param key:       {@link SCCKey}
	 * @param plaintext: as {@link PlaintextContainer}
	 * @return {@link SCCCiphertext}
	 * @throws SCCException
	 */
	public AbstractSCCCiphertext encryptAsymmetric(AbstractSCCKey key, PlaintextContainerInterface plaintext)
			throws SCCException;

	/**
	 * Asymmetric encryption with a certain {@link SCCKey} for a given plaintext
	 * based on the current Secure Crypto Config file.
	 * 
	 * <br> The encryption can be done as follows:
	 * <pre>
	 * {@code
	 * 	SecureCryptoConfig scc = new SecureCryptoConfig();
	 *  SCCCiphertext c = scc.encryptSymmetric(sccKey, plaintext);
	 * }
	 * </pre>
	 * <br>A new {@link SCCKey} for performing can be created with
	 * {@link SCCKey#createKey(KeyUseCase)} as follows:
	 * 
	 * <pre>
	 * {@code
	 * 	SCCKey key = SCCKey.createKey(KeyUseCase.AsymmetricEncryption);
	 * }
	 * </pre>
	 * 
	 * Also it is possible to create a SCCKey from already existing SCCKey byte[]
	 * with {@link SCCKey#createFromExistingKey(byte[])}::
	 * 
	 * <pre>
	 * {@code
	 * SCCKey key = SCCKey.createFromExistingKey(existingSCCKey)
	 * }
	 * </pre>
	 * 
	 * @param key:       {@link SCCKey}
	 * @param plaintext: as byte[]
	 * @return {@link SCCCiphertext}
	 * @throws SCCException
	 */
	public AbstractSCCCiphertext encryptAsymmetric(AbstractSCCKey key, byte[] plaintext)
			throws SCCException;

	/**
	 * 
	 * Ciphertext will be first decrypted and then encrypted based on the current
	 * Secure Crypto Config file.
	 * 
	 * @param key:        {@link SCCKey}
	 * @param ciphertext: {@link SCCCiphertext}
	 * @return {@link SCCCiphertext}
	* @throws SCCException
	 */
	public AbstractSCCCiphertext reEncryptAsymmetric(AbstractSCCKey key, AbstractSCCCiphertext ciphertext)
			throws SCCException;

	/**
	 * Asymmetric decryption with a certain {@link SCCKey} for a given
	 * {@link SCCCiphertext}.
	 * 
	 * @param key:        {@link SCCKey}
	 * @param ciphertext: {@link SCCCiphertext}
	 * @return {@link PlaintextContainer}
	 * @throws SCCException
	 */
	public PlaintextContainerInterface decryptAsymmetric(AbstractSCCKey key, AbstractSCCCiphertext ciphertext)
			throws SCCException;

	// Hashing

	/**
	 * Hashing of a given plaintext based on the current Secure Crypto Config file.
	 * 
	 * <br> The hashing can be done as follows:
	 * <pre>
	 * {@code
	 * 	SecureCryptoConfig scc = new SecureCryptoConfig();
	 *  SCCHash hash = scc.hash(plaintext);
	 * }
	 * </pre>
	 * A PlaintextContainer representation can be done by calling
	 * {@link PlaintextContainer#PlaintextContainer(byte[])} with the byte[]
	 * representation of the plaintext to be hashed.
	 * 
	 * @param plaintext: as {@link PlaintextContainer}
	 * @return {@link SCCHash}
	 * @throws SCCException
	 */
	public AbstractSCCHash hash(PlaintextContainerInterface plaintext) throws SCCException;

	/**
	 * Hashing of a given plaintext based on the current Secure Crypto Config file.
	 * 
	 * <br> The hashing can be done as follows:
	 * <pre>
	 * {@code
	 * 	SecureCryptoConfig scc = new SecureCryptoConfig();
	 *  SCCHash hash = scc.hash(plaintext);
	 * }
	 * </pre>
	 * @param plaintext: as byte[]
	 * @return {@link SCCHash}
	 * @throws SCCException
	 */
	public AbstractSCCHash hash(byte[] plaintext) throws SCCException;

	/**
	 * Given a {@link SCCHash} of a plaintext: the corresponding plaintext will be
	 * hashed again with the current Secure Crypto Config.
	 * 
	 * <br><br>A PlaintextContainer representation can be done by calling
	 * {@link PlaintextContainer#PlaintextContainer(byte[])} with the byte[]
	 * representation of the plaintext to be hashed.
	 * 
	 * @param plaintext: as {@link PlaintextContainer}
	 * @param hash:      {@link SCCHash}
	 * @return {@link SCCHash}
	 * @throws SCCException
	 */
	public AbstractSCCHash updateHash(PlaintextContainerInterface plaintext, AbstractSCCHash hash)
			throws SCCException;

	/**
	 * Given a {@link SCCHash} of a plaintext: the corresponding plaintext will be
	 * hashed again with the current Secure Crypto Config.
	 * 
	 * @param plaintext: as byte[]
	 * @param hash:      {@link SCCHash}
	 * @return {@link SCCHash}
	 * @throws SCCException
	 */
	public AbstractSCCHash updateHash(byte[] plaintext, AbstractSCCHash hash) throws SCCException;

	/**
	 * Validate a given {@link SCCHash} for a specific plaintext.
	 * 
	 * The plaintext will be hashed again and compared if the resulting hash is
	 * identical to the provided one.
	 * 
	 * <br><br>A PlaintextContainer representation can be done by calling
	 * {@link PlaintextContainer#PlaintextContainer(byte[])} with the byte[]
	 * representation of the plaintext to be hashed.
	 * 
	 * @param plaintext: as {@link PlaintextContainer}
	 * @param hash:      {@link SCCHash}
	 * @return boolean
	 * @throws SCCException
	 */
	public boolean validateHash(PlaintextContainerInterface plaintext, AbstractSCCHash hash)
			throws SCCException;

	/**
	 * Validate a given {@link SCCHash} for a specific plaintext.
	 * 
	 * The plaintext will be hashed again and compared if the resulting hash is
	 * identical to the provided one.
	 * 
	 * @param plaintext: as byte[]
	 * @param hash:      {@link SCCHash}
	 * @return boolean
	 * @throws SCCException
	 */
	public boolean validateHash(byte[] plaintext, AbstractSCCHash hash) throws SCCException;

	// Digital Signature

	/** Signing with a certain {@link SCCKey} for a given plaintext based on the
	 * current Secure Crypto Config file.
	 * 
	 * <br> The signing can be done as follows:
	 * <pre>
	 * {@code
	 * 	SecureCryptoConfig scc = new SecureCryptoConfig();
	 *  SCCSignature sig = scc.sign(sccKey, plaintext);
	 * }
	 * </pre>
	 * 
	 * <br>A new {@link SCCKey} for performing can be created with
	 * {@link SCCKey#createKey(KeyUseCase)} as follows:
	 * 
	 * <pre>
	 * {@code
	 * 	SCCKey key = SCCKey.createKey(KeyUseCase.Signing);
	 * }
	 * </pre>
	 * 
	 * Also it is possible to create a SCCKey from already existing SCCKey byte[]
	 * with {@link SCCKey#createFromExistingKey(byte[])}:
	 * 
	 * <pre>
	 * {@code
	 * SCCKey key = SCCKey.createFromExistingKey(existingSCCKey)
	 * }
	 * </pre>
	 * 
	 * A PlaintextContainer representation can be done by calling
	 * {@link PlaintextContainer#PlaintextContainer(byte[])} with the byte[]
	 * representation of the plaintext to be signed.
	 * 
	 * @param key:       {@link SCCKey}
	 * @param plaintext: as {@link PlaintextContainer}
	 * @return {@link SCCSignature}
	 * @throws SCCException
	 */
	public AbstractSCCSignature sign(AbstractSCCKey key, PlaintextContainerInterface plaintext)
			throws SCCException;

	/**
	 * Signing with a certain {@link SCCKey} for a given plaintext based on the
	 * current Secure Crypto Config file.
	 * 
	 * <br> The signing can be done as follows:
	 * <pre>
	 * {@code
	 * 	SecureCryptoConfig scc = new SecureCryptoConfig();
	 *  SCCSignature sig = scc.sign(sccKey, plaintext);
	 * }
	 * </pre>
	 * 
	 * <br>A new {@link SCCKey} for performing can be created with
	 * {@link SCCKey#createKey(KeyUseCase)} as follows:
	 * 
	 * <pre>
	 * {@code
	 * 	SCCKey key = SCCKey.createKey(KeyUseCase.Signing);
	 * }
	 * </pre>
	 * 
	 * Also it is possible to create a SCCKey from already existing SCCKey byte[]
	 * with {@link SCCKey#createFromExistingKey(byte[])}::
	 * 
	 * <pre>
	 * {@code
	 * SCCKey key = SCCKey.createFromExistingKey(existingSCCKey)
	 * }
	 * </pre>
	 * 
	 * @param key:       {@link SCCKey}
	 * @param plaintext: as byte[]
	 * @return {@link SCCSignature}
	 * @throws SCCException
	 */
	public AbstractSCCSignature sign(AbstractSCCKey key, byte[] plaintext)
			throws SCCException;

	/**
	 * Update the exsting {@link SCCSignature} of a plaintext with a new signature
	 * based on the current Secure Crypto Config.
	 * 
	 * <br><br> A PlaintextContainer representation can be done by calling
	 * {@link PlaintextContainer#PlaintextContainer(byte[])} with the byte[]
	 * representation of the plaintext to be signed.
	 * @param key:       {@link SCCKey}
	 * @param plaintext: as {@link PlaintextContainer}
	 * @return {@link SCCSignature}
	 * @throws SCCException
	 */
	public AbstractSCCSignature updateSignature(AbstractSCCKey key, PlaintextContainerInterface plaintext)
			throws SCCException;

	/**
	 * Update the exsting {@link SCCSignature} of a plaintext with a new signature
	 * based on the current Secure Crypto Config.
	 * 
	 * @param key:       {@link SCCKey}
	 * @param plaintext: as byte[]
	 * @return {@link SCCSignature}
	 * @throws SCCException
	 */
	public AbstractSCCSignature updateSignature(AbstractSCCKey key, byte[] plaintext)
			throws SCCException;

	/**
	 * Validate a {@link SCCSignature}.
	 * 
	 * @param key:       {@link AbstractSCCKey}
	 * @param signature: {@link SCCSignature}
	 * @return boolean
	 * @throws SCCException
	 */
	public boolean validateSignature(AbstractSCCKey key, AbstractSCCSignature signature)
			throws SCCException;

	/**
	 * Validate a {@link SCCSignature}.
	 * 
	 * @param key:       {@link AbstractSCCKey}
	 * @param signature: as byte[] representation of {@link SCCSignature}
	 * @return boolean
	 * @throws SCCException
	 */
	public boolean validateSignature(AbstractSCCKey key, byte[] signature) throws SCCException;

	// Password Hashing

	/**
	 * Hash a password based on the current Secure Crypto Config file.
	 * <br> The password hashing can be done as follows:
	 * <pre>
	 * {@code
	 * 	SecureCryptoConfig scc = new SecureCryptoConfig();
	 *  SCCPasswordHash hash = scc.passwordHash(password);
	 * }
	 * </pre>
	 * A PlaintextContainer representation can be done by calling
	 * {@link PlaintextContainer#PlaintextContainer(byte[])} with the byte[]
	 * representation of the password to be hashed.
	 *
	 * @param password: as {@link PlaintextContainer}
	 * @return {@link SCCPasswordHash}
	 * @throws SCCException
	 */
	public AbstractSCCPasswordHash passwordHash(PlaintextContainerInterface password)
			throws SCCException;

	/**
	 * Hash a password based on the current Secure Crypto Config file.
	 * 
	 * <br> The password hashing can be done as follows:
	 * <pre>
	 * {@code
	 * 	SecureCryptoConfig scc = new SecureCryptoConfig();
	 *  SCCPasswordHash hash = scc.passwordHash(password);
	 * }
	 * </pre>
	 * @param password: as byte[]
	 * @return {@link SCCPasswordHash}
	 * @throws SCCException
	 */
	public AbstractSCCPasswordHash passwordHash(byte[] password) throws SCCException;

	/**
	 * Validate a given {@link SCCPasswordHash} against given password.
	 * 
	 * The password will be hashed again and compared if resulting hash is identical
	 * to the given one.
	 * 
	 * @param password:     as {@link PlaintextContainer}
	 * @param passwordhash: {@link SCCPasswordHash}
	 * @return boolean
	 * @throws SCCException
	 */
	public boolean validatePasswordHash(PlaintextContainerInterface password, AbstractSCCPasswordHash passwordhash)
			throws SCCException;

	/**
	 * Validate a given {@link SCCPasswordHash} against given password.
	 * 
	 * The password will be hashed again and compared if resulting hash is identical
	 * to the given one.
	 * 
	 * @param password:     as byte[]
	 * @param passwordhash: {@link SCCPasswordHash}
	 * @return boolean
	 * @throws SCCException
	 */
	public boolean validatePasswordHash(byte[] password, AbstractSCCPasswordHash passwordhash)
			throws SCCException;
}

/**
 * Class for a container representing the plaintext processed in cryptographic
 * use cases.
 * 
 * A PlaintextContainer contains the plaintext as byte[] representation. The
 * class provides various cryptography operations that can be performed on the
 * plaintext (e.g. encryption, signing).
 * 
 * <br><br>To generate a new PlaintextContainer call {@link PlaintextContainer#PlaintextContainer(byte[])}:
 * <pre>
 * {@code
 * PlaintextContainer container = new PlaintextContainer(plaintextBytes);
 * }
 * </pre>
 */
  abstract interface PlaintextContainerInterface {

	/**
	 * Get byte[] representation of {@link PlaintextContainer}
	 * 
	 * @return byte[]
	 */
	 public abstract byte[] toBytes();

	/**
	 * Get String representation of {@link PlaintextContainer} depending on given
	 * Charset. <br>
	 * E.g
	 * 
	 * <pre>
	 * {@code
	 *  PlaintextContainer container = new PlaintextContainer(byte[]);
	 *  String s = container.toString(StandardCharsets.UTF_8);
	 * }
	 * </pre>
	 * 
	 * @param c: charset to use
	 * @return String
	 */
	public abstract String toString(Charset c);

	/**
	 * Returns String representation of PlaintextContainer. As charset "UTF-8" is
	 * used. To choose another charset call
	 * {@link PlaintextContainerInterface#toString(Charset)}
	 * 
	 * @deprecated 
	 * Do not use the Java default toString() Method. Use {@link PlaintextContainer#toString(Charset)}
	 * instead.
	 * 
	 * @return String
	 */
	@Deprecated
	@Override
	public abstract String toString();
	

	/**
	 * Validate a given {@link SCCHash} against a {@link PlaintextContainer} value.
	 * 
	 * The {@link PlaintextContainer} value will be hashed again and compared if
	 * resulting hash is identical to the given one.
	 * 
	 * @param hash: {@link SCCHash}
	 * @return boolean
	 * @throws SCCException
	 */
	public abstract boolean validateHash(AbstractSCCHash hash) throws SCCException;

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
	public abstract boolean validatePasswordHash(AbstractSCCPasswordHash passwordHash) throws SCCException;

	/**
	 * Symmetric encryption with a certain {@link SCCKey} for a given plaintext
	 * based on the current Secure Crypto Config file.
	 * 
	 * <br> The encryption can be done as follows:
	 * <pre>
	 * {@code
	 *  PlaintextContainer c = new PlaintextContainer(plaintextBytes);
	 *  SCCCiphertext ciphertext = c.encryptSymmetric(sccKey);
	 * }
	 * </pre>
	 * <br>A new {@link SCCKey} for performing can be created with
	 * {@link SCCKey#createKey(KeyUseCase)} as follows:
	 * 
	 * <pre>
	 * {@code
	 * 	SCCKey key = SCCKey.createKey(KeyUseCase.SymmetricEncryption);
	 * }
	 * </pre>
	 * 
	 * Alternatively it is also possible to create a key derived from a password
	 * with {@link SCCKey#createSymmetricKeyWithPassword(byte[])}:
	 * 
	 * <pre>
	 * {@code
	 * 	SCCKey key = SCCKey.createSymmetricKeyWithPassword(password);
	 * }
	 * </pre>
	 * 
	 * Also it is possible to create a SCCKey from already existing SCCKey byte[]
	 * with {@link SCCKey#createFromExistingKey(byte[])}::
	 * 
	 * <pre>
	 * {@code
	 * SCCKey key = SCCKey.createFromExistingKey(existingSCCKey)
	 * }
	 * </pre>
	 * 
	 * @param key: {@link SCCKey}
	 * @return {@link SCCCiphertext}
	 * @throws SCCException
	 */
	public abstract AbstractSCCCiphertext encryptSymmetric(AbstractSCCKey key) throws SCCException;

	/**
	 * Asymmetric encryption with a certain {@link SCCKey} for a given plaintext
	 * based on the current Secure Crypto Config file.
	 * <br> The encryption can be done as follows:
	 * <pre>
	 * {@code
	 * 	PlaintextContainer c = new PlaintextContainer(plaintextBytes);
	 *  SCCCiphertext c = c.encryptAsymmetric(sccKey);
	 * }
	 * </pre>
	 * 
	 * <br>A new {@link SCCKey} for performing can be created with
	 * {@link SCCKey#createKey(KeyUseCase)} as follows:
	 * 
	 * <pre>
	 * {@code
	 * 	SCCKey key = SCCKey.createKey(KeyUseCase.AsymmetricEncryption);
	 * }
	 * </pre>
	 * 
	 * Also it is possible to create a SCCKey from already existing SCCKey byte[]
	 * with {@link SCCKey#createFromExistingKey(byte[])}::
	 * 
	 * <pre>
	 * {@code
	 * SCCKey key = SCCKey.createFromExistingKey(existingSCCKey)
	 * }
	 * </pre>
	 * 
	 * @param key: {@link SCCKey}
	 * @return {@link SCCCiphertext}
	 * @throws SCCException
	 */
	public abstract AbstractSCCCiphertext encryptAsymmetric(AbstractSCCKey key) throws SCCException;

	/** Signing with a certain {@link SCCKey} for a given plaintext based on the
	 * current Secure Crypto Config file.
	 * 
	 * <br> The signing can be done as follows:
	 * <pre>
	 * {@code
	 * 	PlaintextContainer c = new PlaintextContainer(plaintextBytes);
	 *  SCCSignature sig = c.sign(sccKey);
	 * }
	 * </pre>
	 * 
	 * <br>A new {@link SCCKey} for performing can be created with
	 * {@link SCCKey#createKey(KeyUseCase)} as follows:
	 * 
	 * <pre>
	 * {@code
	 * 	SCCKey key = SCCKey.createKey(KeyUseCase.Signing);
	 * }
	 * </pre>
	 * 
	 * Also it is possible to create a SCCKey from already existing SCCKey byte[]
	 * with {@link SCCKey#createFromExistingKey(byte[])}::
	 * 
	 * <pre>
	 * {@code
	 * SCCKey key = SCCKey.createFromExistingKey(existingSCCKey)
	 * }
	 * </pre>
	 * 
	 * @param key: {@link SCCKey}
	 * @return {@link SCCSignature}
	 * @throws SCCException
	 */
	public abstract AbstractSCCSignature sign(AbstractSCCKey key) throws SCCException;

	/**
	 * Determines if given signature is valid for a given plaintext
	 * @param signature
	 * @param key
	 * @return boolean shows if Signature for a given plaintext is valid
	 * @throws SCCException 
	 */
	public abstract boolean validateSignature (AbstractSCCSignature signature, AbstractSCCKey key) throws SCCException;
	/**
	 * Hashing of a plaintext ({@link PlaintextContainer}).
	 * 
	 * <br> The hashing can be done as follows:
	 * <pre>
	 * {@code
	 * 	PlaintextContainer c = new PlaintextContainer(plaintextBytes);
	 *  SCCHash hash = c.hash();
	 * }
	 * </pre>
	 * 
	 * @return {@link SCCHash}
	 * @throws SCCException
	 */
	public abstract AbstractSCCHash hash() throws SCCException;

	/**
	 * Assume the plaintext ({@link PlaintextContainer}) represents a password and
	 * perform password hashing.
	 * <br> The password hashing can be done as follows:
	 * <pre>
	 * {@code
	 * 	PlaintextContainer c = new PlaintextContainer(passwordBytes);
	 *  SCCPasswordHash hash = scc.passwordHash();
	 * }
	 * </pre>
	 * 
	 * @return {@link SCCPasswordHash}
	 * @throws SCCException
	 */
	public abstract AbstractSCCPasswordHash passwordHash() throws SCCException;

}

/**
 * Class representing a container for the ciphertext (as result from encrypting a
 * plaintext).
 * 
 * <br><br>SCCCiphertext contains a byte[] representation of a specific COSE message.
 * This message contains the encrypted plaintext as well as all the parameters
 * used during encryption. The inclusion of the used parameters, except the key,
 * in the SCCCiphertext ensures before the decryption no used algorithm or
 * parameters must be specified by the user, but can parse it from the COSE
 * message.
 * 
 * <br><br>For creating a new SCCCiphertext call the method
 * {@link SecureCryptoConfig#encryptSymmetric(AbstractSCCKey, byte[])} or
 * {@link SecureCryptoConfig#encryptAsymmetric(AbstractSCCKey, byte[])}. <br>
 * E.g. as result of symmetric encryption:
 * <pre>
 * {@code
 *  SecureCryptoConfig scc = new SecureCryptoConfig();
 *  SCCCiphertext c = scc.encryptSymmetric(sccKey, plaintextBytes);
 * }
 * </pre>
 * It is also possible to create a SCCCiphertext from an existing SCCCiphertext byte[]
 * representation when calling
 * {@link SCCCiphertext#createFromExistingCiphertext(byte[])}
 *
 */
 abstract class AbstractSCCCiphertext {

	byte[] msg;

	protected AbstractSCCCiphertext(byte[] msg) {
		this.msg = msg;
	}

	/**
	 * Get byte[] representation of {@link SCCCiphertext}.
	 * 
	 * @return byte[]
	 */
	public abstract byte[] toBytes();

	/**
	 * Use {@link SCCCiphertext#toBase64()} instead.
	 * @deprecated 
	 * Do not use the Java default toString() Method. Use {@link SCCCiphertext#toBase64()}
	 * instead.
	 * @return String
	 */
	@Deprecated
	@Override
	public abstract String toString();
	
	/**
	 * Base64 encode {@link SCCCiphertext}.
	 * 
	 * @return String
	 */
	public abstract String toBase64();

	/**
	 * Symmetric decryption with a certain {@link SCCKey} of {@link SCCCiphertext}.
	 * 
	 * @param key: {@link SCCKey}
	 * @return {@link PlaintextContainer}
	 * @throws SCCException
	 */
	public abstract PlaintextContainerInterface decryptSymmetric(AbstractSCCKey key) throws SCCException;

	/**
	 * Asymmetric decryption with a certain {@link SCCKey} of {@link SCCCiphertext}.
	 * 
	 * @param key: {@link SCCKey}
	 * @return {@link PlaintextContainer}
	 * @throws SCCException
	 */
	public abstract PlaintextContainerInterface decryptAsymmetric(AbstractSCCKey key) throws SCCException;

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
	public abstract AbstractSCCCiphertext reEncryptSymmetric(AbstractSCCKey key) throws SCCException;

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
	public abstract AbstractSCCCiphertext reEncryptAsymmetric(AbstractSCCKey key) throws SCCException;

}

/**
 * Class representing a container of a key used for cryptography operations like
 * symmetric or asymmetric encryption.
 * 
 * <br><br>SCCKey contains a byte[] representation of a key as well as different
 * parameters like the type ({@link SCCKey.KeyType}) and the used algorithm for
 * key creation.
 * 
 * <br><br>A new {@link SCCKey} for performing a cryptographic use case can be created with
 * the method {@link SCCKey#createKey(KeyUseCase)}. <br>E.g. creating a key for symmetric encryption:
 * 
 * <pre>
 * {@code
 * 	SCCKey key = SCCKey.createKey(KeyUseCase.SymmetricEncryption);
 * }
 * </pre>
 * Choose a suitable {@link SCCKey.KeyUseCase} for key creation. For doing asymmetric encryption
 * use {@link SCCKey.KeyUseCase#AsymmetricEncryption}. <br>For doing symmetric encryption
 * {@link SCCKey.KeyUseCase#SymmetricEncryption}. <br>
 * For Signing {@link SCCKey.KeyUseCase#Signing}<br><br>
 * Alternatively when performing symmetric encryption it is also possible to create a key derived from a password
 * with {@link SCCKey#createSymmetricKeyWithPassword(byte[])}:
 * 
 * <pre>
 * {@code
 * 	SCCKey key = SCCKey.createSymmetricKeyWithPassword(password);
 * }
 * </pre>
 * 
 * Also it is possible to create a SCCKey from already existing SCCKey byte[]
 * with {@link SCCKey#createFromExistingKey(byte[])}:
 *
 * <pre>
 * {@code
 * SCCKey key = SCCKey.createFromExistingKey(existingSCCKey)
 * }
 * </pre>
 *
 */
 abstract class AbstractSCCKey {

	KeyType type;
	byte[] privateKey;
	byte[] publicKey;
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
	 * @throws SCCException 
	 */
	public abstract byte[] toBytes() throws SCCException;

	/**
	 * Get byte[] representation of public key.
	 * 
	 * @return byte[]: returns byte[] representation of public key in case that the
	 *         key has {@link SCCKey.KeyType#Asymmetric}
	 * @throws SCCException 
	 */
	public abstract byte[] getPublicKeyBytes() throws SCCException;

	/**
	 * Get byte[] representation of private key.
	 * 
	 * @return byte[]: returns byte[] representation of private key in case that the
	 *         key has {@link SCCKey.KeyType#Asymmetric}
	 * @throws SCCException 
	 */
	public abstract byte[] getPrivateKeyBytes() throws SCCException;

	/**
	 * Get {@link KeyType} of {@link SCCKey}.
	 * 
	 * A key can either be {@link SCCKey.KeyType#Symmetric} or
	 * {@link SCCKey.KeyType#Asymmetric}. According to its type a key can be used
	 * for different cryptographic use cases.
	 * 
	 * @return {@link KeyType}
	 */
	public abstract KeyType getKeyType();

	/**
	 * Returns the algorithm used for key generation.
	 * 
	 * @return String: algorithm used for key generation
	 */
	public abstract String getAlgorithm();

}

/**
 * Class representing a container for a cryptographic Hash.
 * 
 * <br><br>SCCHash contains a byte[] representation of a COSE message. The message
 * contains the hash as well as all the parameters used during hashing. The
 * inclusion of the used parameters in the hash ensures that validation
 * implementation code does not need to know the used algorithm or parameters
 * before validation, but can parse it from the COSE message.
 * 
 * <br><br>A new SCCHash can be created by calling {@link SecureCryptoConfig#hash(byte[])}.<br>
 * E.g.
 * <pre>
 * {@code
 * SecureCryptoConfig scc = new SecureCryptoConfig();
 * SCCSignature signature = scc.hash(plaintext);
 * }
 * </pre>
 * Alternatively it is also possible to create a SCCHash from a existing byte[]
 * representation of a SCCHash by calling {@link SCCHash#createFromExistingHash(byte[])}
 */
abstract class AbstractSCCHash {

	byte[] hashMsg;

	/**
	 * Constructor that creates a new SCCHash object based on existing COSE message.
	 * 
	 * @param hashMsg: byte[] of COSE message
	 */
	protected AbstractSCCHash(byte[] hashMsg) {
		this.hashMsg = hashMsg;
	}


	/**
	 * Get byte[] representation of {@link SCCHash}.
	 * 
	 * @return byte[]
	 */
	public abstract byte[] toBytes();

	/**
	 * Use {@link SCCHash#toBase64()} instead.
	 * @deprecated 
	 * Do not use the Java default toString() Method. Use {@link SCCHash#toBase64()}
	 * instead.
	 * @return String
	 */
	@Deprecated
	@Override
	public abstract String toString();
	
	/**
	 * Base64 encode {@link SCCHash}.
	 * 
	 * @return String
	 */
	public abstract String toBase64();

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
	public abstract boolean validateHash(PlaintextContainerInterface plaintext) throws SCCException;

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
	public abstract boolean validateHash(byte[] plaintext) throws SCCException;

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
	public abstract AbstractSCCHash updateHash(PlaintextContainerInterface plaintext) throws SCCException;

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
	public abstract AbstractSCCHash updateHash(byte[] plaintext) throws SCCException;

}

/**
 * Class representing a container for a cryptographic Password Hash.
 * 
 * <br><br>SCCPasswordHash contains a byte[] representation of a COSE message. The byte[]
 * contains the password hash as well as all the parameters used during hashing.
 * The inclusion of the used parameters in the password hash ensures that
 * validation implementation code does not need to know the used algorithm or
 * parameters before validation, but can parse it from the COSE message.
 *
 * <br><br>A new SCCPasswordHash can be created by calling {@link SecureCryptoConfig#passwordHash(byte[])}.<br>
 * E.g.
 * <pre>
 * {@code
 * SecureCryptoConfig scc = new SecureCryptoConfig();
 * SCCSignature signature = scc.passwordHash(password);
 * }
 * </pre>
 * Alternatively it is also possible to create a SCCPasswordHash from a existing byte[]
 * representation of a SCCPaswordHash by calling {@link SCCPasswordHash#createFromExistingPasswordHash(byte[])}
 */
 
abstract class AbstractSCCPasswordHash {

	byte[] hashMsg;

	/**
	 * Constructor that creates a new AbstractSCCPasswordHash object based on
	 * existing COSE message.
	 * 
	 * @param hashMsg: byte[] of COSE message
	 */
	protected AbstractSCCPasswordHash(byte[] hashMsg) {
		this.hashMsg = hashMsg;
	}


	/**
	 * Get byte[] representation of {@link SCCPasswordHash}.
	 * 
	 * @return byte[]
	 */
	public abstract byte[] toBytes();

	/**
	 * Base64 encode {@link SCCPasswordHash}.
	 * 
	 * @return String
	 */
	public abstract String toBase64();
	
	/**
	 * Use {@link SCCPasswordHash#toBase64()} instead.
	 * @deprecated 
	 * Do not use the Java default toString() Method. Use {@link SCCPasswordHash#toBase64()}
	 * instead.
	 * @return String
	 */
	@Deprecated
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
	public abstract boolean validatePasswordHash(PlaintextContainerInterface password) throws SCCException;

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
	public abstract boolean validatePasswordHash(byte[] password) throws SCCException;

}

/**
 * Class representing a container for a Digital Signature.
 * 
 * <br><br>SCCSignature contains a byte[] representation of a COSE message. The byte[]
 * contains the signature as well as all the parameters used during signing. The
 * inclusion of the used parameters in the signature ensures that validation
 * implementation code does not need to know the used algorithm or parameters
 * before validation, but can parse it from the COSE message.
 * 
 * <br><br>A new SCCSignature can be created by calling {@link SecureCryptoConfig#sign(AbstractSCCKey, byte[])}.<br>
 * E.g.
 * <pre>
 * {@code
 * SecureCryptoConfig scc = new SecureCryptoConfig();
 * SCCSignature signature = scc.sign(key, plaintext);
 * }
 * </pre>
 * Alternatively it is also possible to create a SCCSignature from a existing byte[]
 * representation of a SCCSignature by calling {@link SCCSignature#createFromExistingSignature(byte[])}
 */
abstract class AbstractSCCSignature {
	byte[] signatureMsg;

	protected AbstractSCCSignature(byte[] signatureMasg) {
		this.signatureMsg = signatureMasg;
	}

	
	/**
	 * Get byte[] representation of {@link SCCSignature}.
	 * 
	 * @return byte[]
	 */
	public abstract byte[] toBytes();

	/**
	 * Base64 encode {@link AbstractSCCSignature}.
	 * 
	 * @return String
	 */
	public abstract String toBase64();
	
	/**
	 * Use {@link SCCSignature#toBase64()} instead.
	 * @deprecated 
	 * Do not use the Java default toString() Method. Use {@link SCCSignature#toBase64()}
	 * instead.
	 * @return String
	 */
	@Deprecated
	@Override
	public abstract String toString();

	/**
	 * Validate {@link SCCSignature}.
	 * 
	 * @param key: {@link AbstractSCCKey}
	 * @return boolean
	 * @throws SCCException
	 */
	public abstract boolean validateSignature(AbstractSCCKey key) throws SCCException;

	/**
	 * Update signature possibly using a different algorithm/parameters.
	 * 
	 * The corresponding plaintext will be signed again with the current Secure
	 * Crypto Config.
	 * 
	 * @param key:       {@link SCCKey}
	 * @param plaintext: as {@link PlaintextContainer}
	 * @return {@link SCCSignature}
	 * @throws SCCException
	 */
	public abstract AbstractSCCSignature updateSignature(PlaintextContainerInterface plaintext, AbstractSCCKey key)
			throws SCCException;

}
