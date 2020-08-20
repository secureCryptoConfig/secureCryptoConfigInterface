package org.securecryptoconfig;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import COSE.CoseException;

/**
 * Class representing the plaintext processed in cryptographic use cases.
 * 
 * A PlaintextContainer contains the plaintext as byte[] representation. The
 * class provides various cryptography operations that can be performed on the
 * plaintext (e.g. encryption, signing).
 * 
 * @author Lisa
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

	@Override
	public byte[] toBytes() {
		return plaintext;
	}

	@Override
	public String toString(Charset c) {
		return new String(this.plaintext, c);

	}
	
	@Override
	public String toString() {
		return toString(StandardCharsets.UTF_8);
	}

	@Override
	public boolean validateHash(AbstractSCCHash hash) throws SCCException {
		try {
			return scc.validateHash(this, hash);
		} catch (CoseException e) {
			throw new SCCException("Hash validation could not be performed!", e);
		}
	}

	@Override
	public boolean validatePasswordHash(AbstractSCCPasswordHash passwordHash) throws SCCException {
		try {
			return scc.validatePasswordHash(this, passwordHash);
		} catch (CoseException e) {
			throw new SCCException("PasswordHash validation could not be performed!", e);
		}
	}

	@Override
	public SCCCiphertext encryptSymmetric(AbstractSCCKey key) throws SCCException {
		try {
			return scc.encryptSymmetric(key, this);
		} catch (CoseException e) {
			throw new SCCException("Symmetric encryption could not be performed!", e);
		} catch (InvalidKeyException e) {
			throw new SCCException("Symmetric encryption is not possible! Not the right KeyType!", e);
		}
	}

	@Override
	public SCCCiphertext encryptAsymmetric(AbstractSCCKey key) throws SCCException {
		try {
			return scc.encryptAsymmetric(key, this);
		} catch (CoseException e) {
			throw new SCCException("Asymmetric encryption could not be performed!", e);
		} catch (InvalidKeyException e) {
			throw new SCCException("Asymmetric encryption is not possible! Not the right KeyType!", e);
		}
	}

	@Override
	public SCCSignature sign(AbstractSCCKey key) throws SCCException {
		try {
			return scc.sign(key, this);
		} catch (CoseException e) {
			throw new SCCException("Signing could not be performed!", e);
		} catch (InvalidKeyException e) {
			throw new SCCException("Signing is not possible! Not the right KeyType!", e);
		}
	}

	@Override
	public SCCHash hash() throws SCCException {
		try {
			return scc.hash(this);
		} catch (CoseException e) {
			throw new SCCException("Hashing could not be performed!", e);
		}
	}

	@Override
	public SCCPasswordHash passwordHash() throws SCCException {
		try {
			return scc.passwordHash(this);
		} catch (CoseException e) {
			throw new SCCException("Password Hashing could not be performed!", e);
		}
	}

}
