package main;

import java.nio.charset.Charset;

import COSE.CoseException;
import COSE.PasswordHashMessage;

/**
 * Class representing the Hash resulting from executing PasswordHashing
 * @author Lisa
 *
 */
public class SCCPasswordHash extends AbstractSCCPasswordHash {
	
	private SecureCryptoConfig scc = new SecureCryptoConfig();

	/**
	 * Constructor that gets the byte[] representation of the COSE message resulting from PasswordHashing
	 * @param hashMsg
	 */
	public SCCPasswordHash(byte[] hashMsg) {
		super(hashMsg);
	}

	@Override
	public boolean validatePasswordHash(PlaintextContainerInterface password) {
		try {
			return scc.validatePasswordHash(password, this);
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
	public String toString(Charset c) {
		return new String(this.hashMsg, c);
	}
	
	/**
	 * Auxiliary method for converting byte[] back to COSE PasswordHashMessage
	 * @return HashMessage
	 */
	protected PasswordHashMessage convertByteToMsg() {
		try {
			return (PasswordHashMessage) PasswordHashMessage.DecodeFromBytes(this.hashMsg);
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

}
