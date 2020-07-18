package main;

import java.nio.charset.Charset;
import java.security.InvalidKeyException;

import COSE.CoseException;

/**
 * Class representing the plaintext processed in cryptographic use cases.
 * A PlaintextContainer contains the plaintext as byte[] representation.
 * The class provides different methods to easiliy deal with the plaintext.
 * @author Lisa
 *
 */
public class PlaintextContainer implements PlaintextContainerInterface {

	private byte[] plaintext;
	private SecureCryptoConfig scc = new SecureCryptoConfig();
	
	/**
	 * Constructor that gets byte[] representation of plaintext
	 * @param plaintext
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
	public boolean validateHash(AbstractSCCHash hash) {
		try {
			return scc.validateHash(this, hash);
		} catch (CoseException e) {
			e.printStackTrace();
			return false;
		}
	}


	@Override
	public boolean validatePasswordHash(AbstractSCCPasswordHash passwordHash) {
		try {
			return scc.validatePasswordHash(this, passwordHash);
		} catch (CoseException e) {
			e.printStackTrace();
			return false;
		}
	}


	@Override
	public SCCCiphertext encryptSymmetric(AbstractSCCKey key) {
		try {
			return scc.encryptSymmetric(key, this);
		} catch (CoseException | InvalidKeyException e) {
			e.printStackTrace();
			return null;
		}
	}


	@Override
	public SCCCiphertext encryptAsymmetric(AbstractSCCKey keyPair) {
		try {
			return scc.encryptAsymmetric(keyPair, this);
		} catch (CoseException | InvalidKeyException e) {
			e.printStackTrace();
			return null;
		}
	}


	@Override
	public SCCSignature sign(AbstractSCCKey keyPair) {
		try {
			return scc.sign(keyPair, this);
		} catch (CoseException | InvalidKeyException e) {
			e.printStackTrace();
			return null;
		}
	}


	@Override
	public SCCHash hash() {
		try {
			return scc.hash(this);
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}


	@Override
	public SCCPasswordHash passwordHash() {
		try {
			return scc.passwordHash(this);
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}


}
