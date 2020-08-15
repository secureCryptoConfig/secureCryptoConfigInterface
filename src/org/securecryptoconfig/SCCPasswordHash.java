package org.securecryptoconfig;

import java.util.Base64;

import COSE.CoseException;
import COSE.PasswordHashMessage;
import COSE.Sign1Message;

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
	private SCCPasswordHash(byte[] hashMsg) {
		super(hashMsg);
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
	
	/**
	 * Returns a SCCPasswordHash from byte[] representation of existing SCCPasswordHash
	 * @param existingSCCPasswordHash: byte[] representation of existing SCCPasswordHash 
	 * @return SCCPasswordHash form byte[]
	 * @throws SCCException 
	 */
	 public static SCCPasswordHash createFromExistingPasswordHash(byte[] existingSCCPasswordHash) throws SCCException
	 {
		 try {
				PasswordHashMessage msg = (PasswordHashMessage) PasswordHashMessage.DecodeFromBytes(existingSCCPasswordHash);
				 return new SCCPasswordHash(existingSCCPasswordHash);
			} catch (CoseException e) {
				throw new SCCException("No valid SCCPasswordHash byte[] representation", e);
			}
		
	 }

}
