package main;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class SCCSignature extends AbstractSCCSignature{

	public SCCSignature(byte[] signature, AbstractSCCAlgorithmParameters parameters) {
		super(signature, parameters);
	}

	@Override
	public String toString() {
		return Base64.getEncoder().encodeToString(this.signature);
	}

}
