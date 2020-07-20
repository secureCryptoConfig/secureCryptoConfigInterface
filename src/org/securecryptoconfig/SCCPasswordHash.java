package org.securecryptoconfig;

import java.util.Base64;

import COSE.CoseException;
import COSE.PasswordHashMessage;

/**
 * Container for a Cryptographic Password Hash.
 * 
 * SCCHash contains a byte[] representation of a COSE message. The byte[]
 * contains the password hash as well as all the parameters used during hashing.
 * The inclusion of the used parameters in the password hash ensures that
 * validation implementation code does not need to know the used algorithm or
 * parameters before validation, but can parse it from the COSE message.
 * 
 * @author Lisa
 *
 */
public class SCCPasswordHash extends AbstractSCCPasswordHash {

	private SecureCryptoConfig scc = new SecureCryptoConfig();

	/**
	 * Constructor that creates a new SCCPasswordHash object based on existing COSE
	 * message.
	 * 
	 * @param hashMsg: byte[] of COSE message
	 */
	public SCCPasswordHash(byte[] hashMsg) {
		super(hashMsg);
	}

	/**
	 * Constructor that creates a new SCCPasswordHash object based on existing COSE
	 * message.
	 * 
	 * @param hashMsg: Base64 encoded String of COSE message
	 */
	public SCCPasswordHash(String hash) {
		this(Base64.getDecoder().decode(hash));
	}

	@Override
	public boolean validatePasswordHash(PlaintextContainerInterface password) throws SCCException {
		try {
			return scc.validatePasswordHash(password, this);
		} catch (CoseException e) {
			throw new SCCException("PasswordHash validation could not be performed!", e);
		}
	}

	@Override
	boolean validatePasswordHash(byte[] password) throws SCCException {
		return validatePasswordHash(new PlaintextContainer(password));
	}

	@Override
	public byte[] toBytes() {
		return this.hashMsg;
	}

	@Override
	public String toString() {
		return Base64.getEncoder().encodeToString(this.hashMsg);
	}

	/**
	 * Auxiliary method for converting byte[] back to COSE PasswordHashMessage
	 * 
	 * @return HashMessage
	 */
	protected PasswordHashMessage convertByteToMsg() {
		try {
			return (PasswordHashMessage) PasswordHashMessage.DecodeFromBytes(this.hashMsg);
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

}
