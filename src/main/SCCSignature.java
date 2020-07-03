package main;

import java.nio.charset.Charset;

import COSE.CoseException;
import COSE.Sign1Message;

public class SCCSignature extends AbstractSCCSignature {

	SecureCryptoConfig scc = new SecureCryptoConfig();

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
	public SCCSignature updateSignature(PlaintextContainerInterface plaintext, AbstractSCCKeyPair keyPair) {
		try {
			return scc.updateSignature(plaintext, keyPair);
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	@Override
	public boolean validateSignature(AbstractSCCKeyPair keyPair) {
		return scc.validateSignature(keyPair, this);
	}

	protected Sign1Message convertByteToMsg() {
		try {
			return (Sign1Message) Sign1Message.DecodeFromBytes(this.signatureMsg);
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}
	
}
