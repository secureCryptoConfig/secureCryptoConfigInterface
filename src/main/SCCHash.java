package main;

import java.nio.charset.Charset;

import COSE.CoseException;
import COSE.HashMessage;

/**
 * Class representing the Hash resulting from executing hashing. SCCHash
 * includes the byte[] representation of a COSE message. The byte[] contains the
 * hashed plaintext as well as all the parameters used during hashing.
 * 
 * @author Lisa
 *
 */
public class SCCHash extends AbstractSCCHash {

	private SecureCryptoConfig scc = new SecureCryptoConfig();

	/**
	 * Constructor that gets the byte[] representation of the COSE message resulting
	 * from hashing
	 * 
	 * @param hashMsg
	 */
	public SCCHash(byte[] hashMsg) {
		super(hashMsg);
	}

	@Override
	public boolean validateHash(PlaintextContainerInterface plaintext) throws CoseException {
		return scc.validateHash(plaintext, this);
	}

	@Override
	boolean validateHash(byte[] plaintext) throws CoseException {
		return validateHash(new PlaintextContainer(plaintext));
	}

	@Override
	public byte[] toBytes() {
		return this.hashMsg;
	}

	@Override
	public SCCHash updateHash(PlaintextContainerInterface plaintext) throws CoseException {
		return scc.hash(plaintext);

	}

	@Override
	AbstractSCCHash updateHash(byte[] plaintext) throws CoseException {
		return updateHash(new PlaintextContainer(plaintext));
	}

	@Override
	public String toString(Charset c) {
		return new String(this.hashMsg, c);
	}

	/**
	 * Auxiliary method for converting byte[] back to COSE HashMessage
	 * 
	 * @return HashMessage
	 * @throws CoseException
	 */
	protected HashMessage convertByteToMsg() throws CoseException {
		return (HashMessage) HashMessage.DecodeFromBytes(this.hashMsg);

	}
}
