package org.securecryptoconfig;

import java.security.InvalidKeyException;
import java.util.Base64;

import COSE.CoseException;
import COSE.Sign1Message;

/**
 * Container for a Digital Signature.
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
	public SCCSignature(byte[] signatureMsg) {
		super(signatureMsg);
	}

	/**
	 * Constructor that creates a new AbstractSCCSignature object based on existing
	 * COSE message.
	 * 
	 * @param hash: Base64 encoded String of COSE message
	 */
	public SCCSignature(String hash) {
		this(Base64.getDecoder().decode(hash));
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
	public SCCSignature updateSignature(PlaintextContainerInterface plaintext, AbstractSCCKey keyPair)
			throws SCCException {
		try {
			return scc.updateSignature(keyPair, plaintext);
		} catch (CoseException e) {
			throw new SCCException("Signature update could not be performed!", e);
		} catch (InvalidKeyException e) {
			throw new SCCException("Signature update could not be performed! Wrong KeyType!", e);
		}
	}

	@Override
	public boolean validateSignature(AbstractSCCKey keyPair) throws SCCException {
		try {
			return scc.validateSignature(keyPair, this);
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

}
