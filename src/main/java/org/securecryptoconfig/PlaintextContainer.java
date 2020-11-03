package org.securecryptoconfig;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import org.securecryptoconfig.SCCKey.KeyUseCase;

import COSE.CoseException;
import COSE.OneKey;
import COSE.Sign1Message;

/**
 * Class for a container representing the plaintext processed in cryptographic
 * use cases.
 * 
 * A PlaintextContainer contains the plaintext as byte[] representation. The
 * class provides various cryptography operations that can be performed on the
 * plaintext (e.g. encryption, signing).
 * 
 * A new PlaintextContainer can be created like this:
 * 
 * <pre>
 * {
 * 	&#64;code
 * 	String plaintext = "Plaintext";
 * 	PlaintextContainer container = new PlaintextContainer(plaintext.getBytes(StandardCharsets.UTF_8));
 * }
 * </pre>
 * 
 */
public class PlaintextContainer implements PlaintextContainerInterface {

	private byte[] plaintext;
	private SecureCryptoConfig scc = new SecureCryptoConfig();

	/**
	 * Constructor that gets byte[] representation of plaintext
	 * 
	 * @param plaintext: as byte[]
	 */
	public PlaintextContainer(byte[] plaintext) {
		this.plaintext = plaintext;
	}

	/**
	 * Get byte[] representation of {@link PlaintextContainer}
	 * 
	 * @return byte[]
	 */
	@Override
	public byte[] toBytes() {
		return plaintext;
	}

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
	@Override
	public String toString(Charset c) {
		return new String(this.plaintext, c);

	}

	/**
	 * Returns String representation of PlaintextContainer. As charset "UTF-8" is
	 * used. To choose another charset call
	 * {@link PlaintextContainerInterface#toString(Charset)}
	 * 
	 * @deprecated Do not use the Java default toString() Method. Use
	 *             {@link PlaintextContainer#toString(Charset)} instead.
	 * 
	 * @return String
	 */
	@Deprecated
	@Override
	public String toString() {
		return toString(StandardCharsets.UTF_8);
	}

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
	@Override
	public boolean validateHash(AbstractSCCHash hash) throws SCCException {

		return scc.validateHash(this, hash);

	}

	/**
	 * Validate a given {@link SCCPasswordHash} against a {@link PlaintextContainer}
	 * value representing the password.
	 * 
	 * The {@link PlaintextContainer} value will be hashed again and compared if
	 * resulting hash is identical to the given one.
	 * 
	 * @param passwordHash {@link SCCPasswordHash}
	 * @return boolean
	 * @throws SCCException
	 */
	@Override
	public boolean validatePasswordHash(AbstractSCCPasswordHash passwordHash) throws SCCException {

		return scc.validatePasswordHash(this, passwordHash);

	}

	/**
	 * Symmetric encryption with a certain {@link SCCKey} for a given plaintext
	 * based on the current Secure Crypto Config file.
	 * 
	 * <br>
	 * The encryption can be done as follows:
	 * 
	 * <pre>
	 * {
	 * 	&#64;code
	 * 	PlaintextContainer c = new PlaintextContainer(plaintextBytes);
	 * 	SCCCiphertext ciphertext = c.encryptSymmetric(sccKey);
	 * }
	 * </pre>
	 * 
	 * <br>
	 * A new {@link SCCKey} for performing can be created with
	 * {@link SCCKey#createKey(KeyUseCase)} as follows:
	 * 
	 * <pre>
	 * {
	 * 	&#64;code
	 * 	SCCKey key = SCCKey.createKey(KeyUseCase.SymmetricEncryption);
	 * }
	 * </pre>
	 * 
	 * Alternatively it is also possible to create a key derived from a password
	 * with {@link SCCKey#createSymmetricKeyWithPassword(byte[])}:
	 * 
	 * <pre>
	 * {
	 * 	&#64;code
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
	@Override
	public SCCCiphertext encryptSymmetric(AbstractSCCKey key) throws SCCException {

		return scc.encryptSymmetric(key, this);

	}

	/**
	 * Asymmetric encryption with a certain {@link SCCKey} for a given plaintext
	 * based on the current Secure Crypto Config file. <br>
	 * The encryption can be done as follows:
	 * 
	 * <pre>
	 * {
	 * 	&#64;code
	 * 	PlaintextContainer c = new PlaintextContainer(plaintextBytes);
	 * 	SCCCiphertext c = c.encryptAsymmetric(sccKey);
	 * }
	 * </pre>
	 * 
	 * <br>
	 * A new {@link SCCKey} for performing can be created with
	 * {@link SCCKey#createKey(KeyUseCase)} as follows:
	 * 
	 * <pre>
	 * {
	 * 	&#64;code
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
	@Override
	public SCCCiphertext encryptAsymmetric(AbstractSCCKey key) throws SCCException {
		return scc.encryptAsymmetric(key, this);

	}

	/**
	 * Signing with a certain {@link SCCKey} for a given plaintext based on the
	 * current Secure Crypto Config file.
	 * 
	 * <br>
	 * The signing can be done as follows:
	 * 
	 * <pre>
	 * {
	 * 	&#64;code
	 * 	PlaintextContainer c = new PlaintextContainer(plaintextBytes);
	 * 	SCCSignature sig = c.sign(sccKey);
	 * }
	 * </pre>
	 * 
	 * <br>
	 * A new {@link SCCKey} for performing can be created with
	 * {@link SCCKey#createKey(KeyUseCase)} as follows:
	 * 
	 * <pre>
	 * {
	 * 	&#64;code
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
	@Override
	public SCCSignature sign(AbstractSCCKey key) throws SCCException {

		return scc.sign(key, this);

	}

	/**
	 * Determines if given signature is valid for a given plaintext
	 * 
	 * @param signature
	 * @param key
	 * @return boolean shows if Signature for a given plaintext is valid
	 * @throws SCCException
	 */
	@Override
	public boolean validateSignature(AbstractSCCSignature signature, AbstractSCCKey key) throws SCCException {
		try {
			Sign1Message msg = (Sign1Message) COSE.Message.DecodeFromBytes(signature.toBytes());
			msg.SetContent(this.plaintext);
			SCCKey k = (SCCKey) key;
			OneKey oneKey = new OneKey(k.getPublicKey(), k.getPrivateKey());
			
			return msg.validate(oneKey);
			
		} catch (CoseException e) {
			throw new SCCException("No validation possible!", e);
		}
	}

	/**
	 * Hashing of a plaintext ({@link PlaintextContainer}).
	 * 
	 * <br>
	 * The hashing can be done as follows:
	 * 
	 * <pre>
	 * {
	 * 	&#64;code
	 * 	PlaintextContainer c = new PlaintextContainer(plaintextBytes);
	 * 	SCCHash hash = c.hash();
	 * }
	 * </pre>
	 * 
	 * @return {@link SCCHash}
	 * @throws SCCException
	 */
	@Override
	public SCCHash hash() throws SCCException {

		return scc.hash(this);

	}

	/**
	 * Assume the plaintext ({@link PlaintextContainer}) represents a password and
	 * perform password hashing. <br>
	 * The password hashing can be done as follows:
	 * 
	 * <pre>
	 * {
	 * 	&#64;code
	 * 	PlaintextContainer c = new PlaintextContainer(passwordBytes);
	 * 	SCCPasswordHash hash = scc.passwordHash();
	 * }
	 * </pre>
	 * 
	 * @return {@link SCCPasswordHash}
	 * @throws SCCException
	 */
	@Override
	public SCCPasswordHash passwordHash() throws SCCException {

		return scc.passwordHash(this);

	}

}
