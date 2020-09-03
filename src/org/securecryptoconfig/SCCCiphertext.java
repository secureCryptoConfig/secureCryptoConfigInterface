package org.securecryptoconfig;

import java.security.InvalidKeyException;
import java.util.Base64;

import COSE.CoseException;
import COSE.Encrypt0Message;

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
public class SCCCiphertext extends AbstractSCCCiphertext {

	private SecureCryptoConfig scc = new SecureCryptoConfig();

	/**
	 * Constructor that creates a new SCCCiphertext object based on existing COSE
	 * message (ciphertext) bytes.
	 * 
	 * @param msg: byte[] of COSE message
	 */
	private SCCCiphertext(byte[] msg) {
		super(msg);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public byte[] toBytes() {
		return this.msg;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String toString() {
		return toBase64();
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public String toBase64() {
		return Base64.getEncoder().encodeToString(this.msg);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public PlaintextContainer decryptSymmetric(AbstractSCCKey key) throws SCCException {
		try {
			return scc.decryptSymmetric(key, this);
		} catch (CoseException e) {
			throw new SCCException("Symmetric decryption could not be performed!", e);
		} catch (InvalidKeyException e) {
			throw new SCCException("Symmetric decryption is not possible! Not the right KeyType!", e);
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public PlaintextContainer decryptAsymmetric(AbstractSCCKey key) throws SCCException {
		try {
			return scc.decryptAsymmetric(key, this);
		} catch (CoseException e) {
			throw new SCCException("Asymmetric decryption could not be performed!", e);
		} catch (InvalidKeyException e) {
			throw new SCCException("Asymmetric decryption is not possible! Not the right KeyType!", e);
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public SCCCiphertext reEncryptSymmetric(AbstractSCCKey key) throws SCCException {
		try {
			return scc.reEncryptSymmetric(key, this);
		} catch (CoseException e) {
			throw new SCCException("Symmetric ReEncryption could not be performed!", e);
		} catch (InvalidKeyException e) {
			throw new SCCException("Symmetric ReEncryption is not possible! Not the right KeyType!", e);
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public SCCCiphertext reEncryptAsymmetric(AbstractSCCKey keyPair) throws SCCException {
		try {
			return scc.reEncryptAsymmetric(keyPair, this);
		} catch (CoseException e) {
			throw new SCCException("Asymmetric ReEncryption could not be performed!", e);
		} catch (InvalidKeyException e) {
			throw new SCCException("Asymmetric ReEncryption is not possible! Not the right KeyType!", e);
		}
	}
	
	/**
	 * Returns a SCCCiphertext from byte[] representation of existing SCCCiphertext
	 * @param existingSCCCiphertext: byte[] representation of existing SCCCiphertext 
	 * @return SCCCiphertext from byte[]
	 * @throws SCCException 
	 */
	 public static SCCCiphertext createFromExistingCiphertext(byte[] existingSCCCiphertext) throws SCCException
	 {
		 try {
				Encrypt0Message.DecodeFromBytes(existingSCCCiphertext);
				 return new SCCCiphertext(existingSCCCiphertext);
			} catch (CoseException e) {
				throw new SCCException("No valid SCCCiphertext byte[] representation", e);
			}
		
	 }
	 
	 /**
		 * Returns a SCCCiphertext from String (Base64) representation of existing SCCCiphertext
		 * @param existingSCCCiphertext: String (Base64) representation of existing SCCCiphertext 
		 * @return SCCCiphertext from String (Base64)
		 * @throws SCCException 
		 */
		 public static SCCCiphertext createFromExistingCiphertext(String existingSCCCiphertext) throws SCCException
		 {
			 try {
					Encrypt0Message.DecodeFromBytes(Base64.getDecoder().decode(existingSCCCiphertext));
					 return new SCCCiphertext(Base64.getDecoder().decode(existingSCCCiphertext));
				} catch (CoseException e) {
					throw new SCCException("No valid SCCCiphertext String representation", e);
				}
			
		 }

}
