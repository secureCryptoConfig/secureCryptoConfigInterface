package main;

import COSE.OneKey;

public class SCCAlgorithmParameters extends AbstractSCCAlgorithmParameters {

	// for symmetric 
	SCCAlgorithmParameters(byte[] nonce, int tagLength, String algo) {
		super(nonce, tagLength, algo);
	}

	// for asymmetric
	SCCAlgorithmParameters(String algo) {
		super(algo);
	}

	// for signing
	SCCAlgorithmParameters(String algo, PlaintextContainerInterface plaintext) {
		super(algo, plaintext);
	}
	
	//passwordHash
	SCCAlgorithmParameters(String algo, byte[] salt, int keysize, int iterations) {
		super(algo, salt, keysize, iterations);
	}
	
	SCCAlgorithmParameters(OneKey k) {
		super(k);
	}

}
