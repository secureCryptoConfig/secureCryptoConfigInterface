package main;

import java.nio.charset.Charset;

import COSE.CoseException;
import COSE.PasswordHashMessage;

public class SCCPasswordHash extends AbstractSCCPasswordHash {
	
	SecureCryptoConfig scc = new SecureCryptoConfig();

	public SCCPasswordHash(PlaintextContainer password, PlaintextContainer hash, byte[] hashMsg) {
		super(password, hashMsg);
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
	
	protected PasswordHashMessage convertByteToMsg() {
		try {
			return (PasswordHashMessage) PasswordHashMessage.DecodeFromBytes(this.hashMsg);
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

}
