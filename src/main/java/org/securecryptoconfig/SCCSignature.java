package org.securecryptoconfig;

import java.util.Base64;

import com.upokecenter.cbor.CBORException;

import COSE.CoseException;
import COSE.Sign1Message;

/**
 * Class representing a container for a Digital Signature.
 * 
 * <br>
 * <br>
 * SCCSignature contains a byte[] representation of a COSE message. The byte[]
 * contains the signature as well as all the parameters used during signing. The
 * inclusion of the used parameters in the signature ensures that validation
 * implementation code does not need to know the used algorithm or parameters
 * before validation, but can parse it from the COSE message.
 * 
 * <br>
 * <br>
 * A new SCCSignature can be created by calling
 * {@link SecureCryptoConfig#sign(AbstractSCCKey, byte[])}.<br>
 * E.g.
 * 
 * <pre>
 * {
 * 	&#64;code
 * 	SecureCryptoConfig scc = new SecureCryptoConfig();
 * 	SCCSignature signature = scc.sign(key, plaintext);
 * }
 * </pre>
 * 
 * Alternatively it is also possible to create a SCCSignature from a existing
 * byte[] representation of a SCCSignature by calling
 * {@link SCCSignature#createFromExistingSignature(byte[])}
 */
public class SCCSignature extends AbstractSCCSignature {

	private static org.apache.logging.log4j.Logger logger = org.apache.logging.log4j.LogManager
			.getLogger(SCCSignature.class);

	private SecureCryptoConfig scc = new SecureCryptoConfig();

	/**
	 * Constructor that creates a new SCCSignature object based on existing COSE
	 * message (signature) bytes.
	 * 
	 * @param signatureMsg: byte[] of COSE message
	 */
	private SCCSignature(byte[] signatureMsg) {

		super(signatureMsg);

	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public byte[] toBytes() {
		return this.signatureMsg;
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
	public String toBase64() {
		return Base64.getEncoder().encodeToString(this.signatureMsg);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public SCCSignature updateSignature(PlaintextContainerInterface plaintext, AbstractSCCKey key) throws SCCException {

		return scc.updateSignature(key, plaintext);

	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean validateSignature(AbstractSCCKey key) throws SCCException {

		return scc.validateSignature(key, this);

	}

	/**
	 * Auxiliary method for converting byte[] to COSE Sign1Message
	 * 
	 * @return HashMessage
	 */
	protected Sign1Message convertByteToMsg() {
		try {
			return (Sign1Message) COSE.Message.DecodeFromBytes(this.signatureMsg);
		} catch (CBORException | CoseException e) {
			logger.warn("Error while decoding from bytes. Not in COSE format?", e);
			return null;
		}
	}

	/**
	 * Return SCCSignature from byte[] representation of a existing SCCSignature
	 * 
	 * @param existingSCCSignature: byte[] of existing SCCSignature
	 * @return SCCSignature
	 * @throws SCCException
	 */
	public static SCCSignature createFromExistingSignature(byte[] existingSCCSignature) throws SCCException {
		try {
			COSE.Message.DecodeFromBytes(existingSCCSignature);
			return new SCCSignature(existingSCCSignature);
		} catch (CBORException | CoseException e) {
			throw new SCCException("No valid SCCSignature byte[] representation", e);
		}

	}

	/**
	 * Return SCCSignature from String (Base64) representation of a existing
	 * SCCSignature
	 * 
	 * @param existingSCCSignature: String (Base64) of existing SCCSignature
	 * @return SCCSignature
	 * @throws SCCException
	 */
	public static SCCSignature createFromExistingSignature(String existingSCCSignature) throws SCCException {
		try {
			COSE.Message.DecodeFromBytes(Base64.getDecoder().decode(existingSCCSignature));
			return new SCCSignature(Base64.getDecoder().decode(existingSCCSignature));
		} catch (CoseException e) {
			throw new SCCException("No valid SCCSignature String representation", e);
		}

	}

}
