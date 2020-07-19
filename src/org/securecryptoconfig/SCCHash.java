package org.securecryptoconfig;

import java.util.Base64;

import COSE.CoseException;
import COSE.HashMessage;

/**
 * Container for a Cryptographic Hash.
 * 
 * SCCHash contains a byte[] representation of a COSE message. The byte[]
 * contains the hash as well as all the parameters used during hashing. The
 * inclusion of the used parameters in the hash ensures that validation
 * implementation code does not need to know the used algorithm or parameters
 * before validation, but can parse it from the COSE message.
 * 
 * @author Lisa
 *
 */
public class SCCHash extends AbstractSCCHash {

	private SecureCryptoConfig scc = new SecureCryptoConfig();

	/**
	 * Constructor that creates a new SCCHash object based on existing COSE message.
	 * 
	 * @param hashMsg: byte[] of COSE message
	 */
	public SCCHash(byte[] hashMsg) {
		super(hashMsg);
	}

	/**
	 * Constructor that creates a new SCCHash object based on existing COSE message.
	 * 
	 * @param hashMsg: Base64 encoded String of COSE message
	 */
	public SCCHash(String hash) {
		this(Base64.getDecoder().decode(hash));
	}

	@Override
	public boolean validateHash(PlaintextContainerInterface plaintext) throws SCCException {
		try {
			return scc.validateHash(plaintext, this);
		} catch (CoseException e) {
			throw new SCCException("Hash validation could not be performed!", e);
		}
	}

	@Override
	boolean validateHash(byte[] plaintext) throws SCCException {
		return validateHash(new PlaintextContainer(plaintext));
	}

	@Override
	public byte[] toBytes() {
		return this.hashMsg;
	}

	@Override
	public SCCHash updateHash(PlaintextContainerInterface plaintext) throws SCCException {
		try {
			return scc.hash(plaintext);
		} catch (CoseException e) {
			throw new SCCException("Hash updating could not be performed!", e);
		}
	}

	@Override
	AbstractSCCHash updateHash(byte[] plaintext) throws SCCException {
		return updateHash(new PlaintextContainer(plaintext));
	}

	@Override
	public String toString() {
		return Base64.getEncoder().encodeToString(this.hashMsg);
	}

	/**
	 * Auxiliary method for converting byte[] back to COSE HashMessage
	 * 
	 * @return HashMessage
	 */
	protected HashMessage convertByteToMsg() {
		try {
			return (HashMessage) HashMessage.DecodeFromBytes(this.hashMsg);
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}
}
