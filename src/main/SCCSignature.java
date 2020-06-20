package main;

import java.util.Base64;

public class SCCSignature extends AbstractSCCSignature{

	public SCCSignature(byte[] signatureMsg) {
		super(signatureMsg);
	}

	@Override
	public String toString() {
		return Base64.getEncoder().encodeToString(this.signatureMsg);
	}
	
	@Override
	public byte[] getSignatureMsg() {
		return this.signatureMsg;
	}

}
