package org.securecryptoconfig;

import java.util.Base64;

import COSE.CoseException;
import COSE.HashMessage;
import COSE.PasswordHashMessage;

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
	private SCCHash(byte[] hashMsg) {
		super(hashMsg);
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
	
	/**
	 * Returns a SCCHash from byte[] representation of existing SCCHash
	 * @param existingSCCHash: byte[] representation of existing SCCHash 
	 * @return SCCHash form byte[]
	 * @throws SCCException 
	 */
	 public static SCCHash createFromExistingHash(byte[] existingSCCHash) throws SCCException
	 {
		 try {
				PasswordHashMessage msg = (PasswordHashMessage) PasswordHashMessage.DecodeFromBytes(existingSCCHash);
				 return new SCCHash(existingSCCHash);
			} catch (CoseException e) {
				throw new SCCException("No valid SCCHash byte[] representation", e);
			}
	 }
}
