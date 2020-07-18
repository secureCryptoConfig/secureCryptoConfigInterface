package main;

import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import COSE.CoseException;

/**
 * Class representing the plaintext processed in cryptographic use cases. A
 * PlaintextContainer contains the plaintext as byte[] representation. The class
 * provides different methods to easiliy deal with the plaintext.
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
	public boolean validateHash(AbstractSCCHash hash) throws CoseException {
		return scc.validateHash(this, hash);

	}

	@Override
	public boolean validatePasswordHash(AbstractSCCPasswordHash passwordHash) throws CoseException {
		return scc.validatePasswordHash(this, passwordHash);

	}

	@Override
	public SCCCiphertext encryptSymmetric(AbstractSCCKey key) throws InvalidKeyException, CoseException {
		return scc.encryptSymmetric(key, this);

	}

	@Override
	public SCCCiphertext encryptAsymmetric(AbstractSCCKey keyPair) throws InvalidKeyException, CoseException,
			IllegalStateException, InvalidKeySpecException, NoSuchAlgorithmException {
		return scc.encryptAsymmetric(keyPair, this);

	}

	@Override
	public SCCSignature sign(AbstractSCCKey keyPair)
			throws InvalidKeyException, CoseException, InvalidKeySpecException, NoSuchAlgorithmException {
		return scc.sign(keyPair, this);

	}

	@Override
	public SCCHash hash() throws CoseException {
		return scc.hash(this);

	}

	@Override
	public SCCPasswordHash passwordHash() throws CoseException {
		return scc.passwordHash(this);
	}

}
