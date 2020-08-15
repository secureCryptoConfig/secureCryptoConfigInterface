package org.securecryptoconfig;

import java.security.InvalidKeyException;
import java.util.Base64;

import COSE.CoseException;
import COSE.Sign1Message;

/**
 * Container for a digital signature. 
 * 
 * Must not be used for creating a new signature.
 * A new SCCSignature can be created with {@link SecureCryptoConfig#sign(AbstractSCCKey, byte[])} 
 * or {@link SecureCryptoConfig#sign(AbstractSCCKey, PlaintextContainerInterface)}
 * 
 * SCCSignature contains a byte[] representation of a COSE message. The byte[]
 * contains the signature as well as all the parameters used during signing. The
 * inclusion of the used parameters in the signature ensures that validation
 * implementation code does not need to know the used algorithm or parameters
 * before validation, but can parse it from the COSE message.
 * 
 * @author Lisa
 *
 */
public class SCCSignature extends AbstractSCCSignature {

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
	
	


	@Override
	public byte[] toBytes() {
		return this.signatureMsg;
	}

	@Override
	public String toString() {
		return Base64.getEncoder().encodeToString(this.signatureMsg);
	}

	@Override
	public SCCSignature updateSignature(PlaintextContainerInterface plaintext, AbstractSCCKey key)
			throws SCCException {
		try {
			return scc.updateSignature(key, plaintext);
		} catch (CoseException e) {
			throw new SCCException("Signature update could not be performed!", e);
		} catch (InvalidKeyException e) {
			throw new SCCException("Signature update could not be performed! Wrong KeyType!", e);
		}
	}

	@Override
	public boolean validateSignature(AbstractSCCKey key) throws SCCException {
		try {
			return scc.validateSignature(key, this);
		} catch (InvalidKeyException e) {
			throw new SCCException("Signature validation could not be performed! Wrong KeyType!", e);
		}
	}

	/**
	 * Auxiliary method for converting byte[] to COSE Sign1Message
	 * 
	 * @return HashMessage
	 */
	protected Sign1Message convertByteToMsg() {
		try {
			return (Sign1Message) Sign1Message.DecodeFromBytes(this.signatureMsg);
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Return SCCSignature from byte[] representation of a existing SCCSignature
	 * @param existingSCCSignature: byte[] of existing SCCSignature
	 * @return SCCSignature
	 * @throws SCCException 
	 */
	public static SCCSignature createFromExistingSignature(byte[] existingSCCSignature) throws SCCException
	{
		try {
			Sign1Message.DecodeFromBytes(existingSCCSignature);
			return new SCCSignature(existingSCCSignature);
		} catch (CoseException e) {
			throw new SCCException("No valid SCCSignature byte[] representation", e);
		}
		
		
	}
	
	/**
	 * Return SCCSignature from String (Base64) representation of a existing SCCSignature
	 * @param existingSCCSignature: String (Base64) of existing SCCSignature
	 * @return SCCSignature
	 * @throws SCCException 
	 */
	public static SCCSignature createFromExistingSignature(String existingSCCSignature) throws SCCException
	{
		try {
			Sign1Message.DecodeFromBytes(Base64.getDecoder().decode(existingSCCSignature));
			return new SCCSignature(Base64.getDecoder().decode(existingSCCSignature));
		} catch (CoseException e) {
			throw new SCCException("No valid SCCSignature String representation", e);
		}
		
		
	}
	
}
