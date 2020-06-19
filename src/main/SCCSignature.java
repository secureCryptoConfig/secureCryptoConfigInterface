package main;

import java.util.Base64;

public class SCCSignature extends AbstractSCCSignature{

	public SCCSignature(byte[] signature) {
		super(signature);
	}

	@Override
	public String toString() {
		return Base64.getEncoder().encodeToString(this.signature);
	}

}
