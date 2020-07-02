package main;

import java.nio.charset.Charset;
import COSE.CoseException;
import COSE.HashMessage;

public class SCCHash extends AbstractSCCHash{

	SecureCryptoConfig scc = new SecureCryptoConfig();
	
	public SCCHash(PlaintextContainer plaintext, byte[] hashMsg)
	{
		super(plaintext, hashMsg);
	}
	
	@Override
	public boolean validateHash(PlaintextContainerInterface plain) {
		try {
			return scc.validateHash(plain, this);
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
	public SCCHash updateHash() {
		try {
			return scc.hash(this.plaintext);
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

	@Override
	public String toString(Charset c) {
		return new String(this.hashMsg, c);
	}
	
	
	protected HashMessage convertByteToMsg() {
		try {
			return (HashMessage) HashMessage.DecodeFromBytes(this.hashMsg);
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

}
