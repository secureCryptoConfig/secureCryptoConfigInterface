package main;

import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import COSE.CoseException;
import COSE.Sign1Message;

/**
 * Class representing Signature resulting from signing. SCCSignature includes a
 * byte[] representation of a COSE message. The byte[] contains the signature as
 * well as all the parameters used during signing. In this way it is possible to
 * validate the SCCSignature with the right choice of parameters easily.
 * 
 * @author Lisa
 *
 */
public class SCCSignature extends AbstractSCCSignature {

	private SecureCryptoConfig scc = new SecureCryptoConfig();

	/**
	 * Constructor that gets the byte[] representation of the COSE message resulting
	 * from signing
	 * 
	 * @param hashMsg
	 */
	public SCCSignature(byte[] signatureMsg) {
		super(signatureMsg);
	}

	@Override
	public byte[] toBytes() {
		return this.signatureMsg;
	}

	@Override
	public String toString(Charset c) {
		return new String(this.signatureMsg, c);
	}

	@Override
	public SCCSignature updateSignature(PlaintextContainerInterface plaintext, AbstractSCCKey keyPair)
			throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, CoseException {
		return scc.updateSignature(keyPair, plaintext);
	}

	@Override
	public boolean validateSignature(AbstractSCCKey keyPair)
			throws InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException {
		return scc.validateSignature(keyPair, this);
	}

	/**
	 * Auxiliary method for converting byte[] back to COSE Sign1Message
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
