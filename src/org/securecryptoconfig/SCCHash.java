package org.securecryptoconfig;

import java.util.Base64;

import COSE.CoseException;
import COSE.HashMessage;

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
				HashMessage.DecodeFromBytes(existingSCCHash);
				 return new SCCHash(existingSCCHash);
			} catch (CoseException e) {
				throw new SCCException("No valid SCCHash byte[] representation", e);
			}
	 }
	 
	 /**
		 * Returns a SCCHash from String (Base64) representation of existing SCCHash
		 * @param existingSCCHash: String (Base64) representation of existing SCCHash 
		 * @return SCCHash from String (Base64)
		 * @throws SCCException 
		 */
		 public static SCCHash createFromExistingHash(String existingSCCHash) throws SCCException
		 {
			 try {
					HashMessage.DecodeFromBytes(Base64.getDecoder().decode(existingSCCHash));
					 return new SCCHash(Base64.getDecoder().decode(existingSCCHash));
				} catch (CoseException e) {
					throw new SCCException("No valid SCCHash String representation", e);
				}
		 }
}
