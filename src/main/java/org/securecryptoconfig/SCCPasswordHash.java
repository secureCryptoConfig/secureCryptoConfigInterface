package org.securecryptoconfig;

import java.util.Base64;

import com.upokecenter.cbor.CBORException;

import COSE.CoseException;
import COSE.PasswordHashMessage;

/**
 * Class representing a container for a cryptographic Password Hash.
 * 
 * <br>
 * <br>
 * SCCPasswordHash contains a byte[] representation of a COSE message. The
 * byte[] contains the password hash as well as all the parameters used during
 * hashing. The inclusion of the used parameters in the password hash ensures
 * that validation implementation code does not need to know the used algorithm
 * or parameters before validation, but can parse it from the COSE message.
 *
 * <br>
 * <br>
 * A new SCCPasswordHash can be created by calling
 * {@link SecureCryptoConfig#passwordHash(byte[])}.<br>
 * E.g.
 * 
 * <pre>
 * {
 * 	&#64;code
 * 	SecureCryptoConfig scc = new SecureCryptoConfig();
 * 	SCCPasswordHash passwordHash = scc.passwordHash(password);
 * }
 * </pre>
 * 
 * Alternatively it is also possible to create a SCCPasswordHash from a existing
 * byte[] representation of a SCCPaswordHash by calling
 * {@link SCCPasswordHash#createFromExistingPasswordHash(byte[])}
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

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean validatePasswordHash(PlaintextContainerInterface password) throws SCCException {

		return scc.validatePasswordHash(password, this);

	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean validatePasswordHash(byte[] password) throws SCCException {
		return validatePasswordHash(new PlaintextContainer(password));
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public byte[] toBytes() {
		return this.hashMsg;
	}

	/**
	 * {@inheritDoc}
	 * @deprecated
	 */
	@Deprecated
	@Override
	public String toString() {
		return toBase64();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String toBase64() {
		return Base64.getEncoder().encodeToString(this.hashMsg);
	}

	/**
	 * Auxiliary method for converting byte[] back to COSE PasswordHashMessage
	 * 
	 * @return HashMessage
	 * @throws CoseException 
	 */
	protected PasswordHashMessage convertByteToMsg() throws CoseException {
	
			return (PasswordHashMessage) COSE.Message.DecodeFromBytes(this.hashMsg);
		
	}

	/**
	 * Returns a SCCPasswordHash from byte[] representation of existing
	 * SCCPasswordHash
	 * 
	 * @param existingSCCPasswordHash: byte[] representation of existing
	 *                                 SCCPasswordHash
	 * @return SCCPasswordHash from byte[]
	 * @throws SCCException
	 */
	public static SCCPasswordHash createFromExistingPasswordHash(byte[] existingSCCPasswordHash) throws SCCException {
		try {
			COSE.Message.DecodeFromBytes(existingSCCPasswordHash);
			return new SCCPasswordHash(existingSCCPasswordHash);
		} catch (CBORException| CoseException e) {
			throw new SCCException("No valid SCCPasswordHash byte[] representation", e);
		}

	}

	/**
	 * Returns a SCCPasswordHash from String (Base64) representation of existing
	 * SCCPasswordHash
	 * 
	 * @param existingSCCPasswordHash: String (Base64) representation of existing
	 *                                 SCCPasswordHash
	 * @return SCCPasswordHash from String (Base64)
	 * @throws SCCException
	 */
	public static SCCPasswordHash createFromExistingPasswordHash(String existingSCCPasswordHash) throws SCCException {
		try {
			COSE.Message.DecodeFromBytes(Base64.getDecoder().decode(existingSCCPasswordHash));
			return new SCCPasswordHash(Base64.getDecoder().decode(existingSCCPasswordHash));
		} catch (CBORException| CoseException e) {
			throw new SCCException("No valid SCCPasswordHash String representation", e);
		}

	}

}
