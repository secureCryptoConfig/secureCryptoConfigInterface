package org.securecryptoconfig;

import java.util.Base64;

import com.upokecenter.cbor.CBORException;

import COSE.CoseException;
import COSE.HashMessage;

/**
 * Class representing a container for a cryptographic Hash.
 * 
 * <br>
 * <br>
 * SCCHash contains a byte[] representation of a COSE message. The message
 * contains the hash as well as all the parameters used during hashing. The
 * inclusion of the used parameters in the hash ensures that validation
 * implementation code does not need to know the used algorithm or parameters
 * before validation, but can parse it from the COSE message.
 * 
 * <br>
 * <br>
 * A new SCCHash can be created by calling
 * {@link SecureCryptoConfig#hash(byte[])}.<br>
 * E.g.
 * 
 * <pre>
 * {
 * 	&#64;code
 * 	SecureCryptoConfig scc = new SecureCryptoConfig();
 * 	SCCHash hash = scc.hash(plaintext);
 * }
 * </pre>
 * 
 * Alternatively it is also possible to create a SCCHash from a existing byte[]
 * representation of a SCCHash by calling
 * {@link SCCHash#createFromExistingHash(byte[])}
 */
public class SCCHash extends AbstractSCCHash {

	private static org.apache.logging.log4j.Logger logger = org.apache.logging.log4j.LogManager
			.getLogger(SCCHash.class);

	private SecureCryptoConfig scc = new SecureCryptoConfig();

	/**
	 * Constructor that creates a new SCCHash object based on existing COSE message.
	 * 
	 * @param hashMsg: byte[] of COSE message
	 */
	private SCCHash(byte[] hashMsg) {
		super(hashMsg);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean validateHash(PlaintextContainerInterface plaintext) throws SCCException {

		return scc.validateHash(plaintext, this);

	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean validateHash(byte[] plaintext) throws SCCException {
		return validateHash(new PlaintextContainer(plaintext));
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
	 */
	@Override
	public SCCHash updateHash(PlaintextContainerInterface plaintext) throws SCCException {

		return scc.hash(plaintext);

	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public AbstractSCCHash updateHash(byte[] plaintext) throws SCCException {
		return updateHash(new PlaintextContainer(plaintext));
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String toBase64() {
		return Base64.getEncoder().encodeToString(this.hashMsg);
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
	 * Auxiliary method for converting byte[] back to COSE HashMessage
	 * 
	 * @return HashMessage
	 * @throws CoseException 
	 */
	protected HashMessage convertByteToMsg() throws CoseException {
	
			return (HashMessage) COSE.Message.DecodeFromBytes(this.hashMsg);
		
	}

	/**
	 * Returns a SCCHash from byte[] representation of existing SCCHash
	 * 
	 * @param existingSCCHash: byte[] representation of existing SCCHash
	 * @return SCCHash form byte[]
	 * @throws SCCException
	 */
	public static SCCHash createFromExistingHash(byte[] existingSCCHash) throws SCCException {
		try {
			COSE.Message.DecodeFromBytes(existingSCCHash);
			return new SCCHash(existingSCCHash);
		} catch (CBORException | CoseException e) {
			throw new SCCException("No valid SCCHash byte[] representation", e);
		}
	}

	/**
	 * Returns a SCCHash from String (Base64) representation of existing SCCHash
	 * 
	 * @param existingSCCHash: String (Base64) representation of existing SCCHash
	 * @return SCCHash from String (Base64)
	 * @throws SCCException
	 */
	public static SCCHash createFromExistingHash(String existingSCCHash) throws SCCException {
		try {
			COSE.Message.DecodeFromBytes(Base64.getDecoder().decode(existingSCCHash));
			return new SCCHash(Base64.getDecoder().decode(existingSCCHash));
		} catch (CBORException | CoseException e) {
			throw new SCCException("No valid SCCHash String representation", e);
		}
	}
}
