package main;

public class SCCAlgorithmParameters extends AbstractSCCAlgorithmParameters {

	// for File en/decrypt (no COSE support)
	
	SCCAlgorithmParameters(byte[] nonce, int tagLength, String algo) {
		super(nonce, tagLength, algo);
	}

}
