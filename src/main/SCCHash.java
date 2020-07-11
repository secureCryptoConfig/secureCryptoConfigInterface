package main;

import java.nio.charset.Charset;
import COSE.CoseException;
import COSE.HashMessage;


/**
 * Class representing the Hash resulting from executing hashing
 * @author Lisa
 *
 */
public class SCCHash extends AbstractSCCHash{

	private SecureCryptoConfig scc = new SecureCryptoConfig();
	
	/**
	 * Constructor that gets the byte[] representation of the COSE message resulting from hashing
	 * @param hashMsg
	 */
	public SCCHash(byte[] hashMsg)
	{
		super(hashMsg);
	}
	
	@Override
	public boolean validateHash(PlaintextContainerInterface plaintext) {
		try {
			return scc.validateHash(plaintext, this);
		} catch (CoseException e) {
			e.printStackTrace();
			return false;
		}
	}

	@Override
	public byte[] toBytes() {
		return this.hashMsg;
	}

	
	@Override
	public SCCHash updateHash(PlaintextContainerInterface plaintext) {
		try {
			return scc.hash(plaintext);
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

	@Override
	public String toString(Charset c) {
		return new String(this.hashMsg, c);
	}
	
	/**
	 * Auxiliary method for converting byte[] back to COSE HashMessage
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

}
