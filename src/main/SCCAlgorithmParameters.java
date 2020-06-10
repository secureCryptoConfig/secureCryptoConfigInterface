package main;

import java.util.HashMap;

public class SCCAlgorithmParameters extends AbstractSCCAlgorithmParameters {

	// for symmetric
	SCCAlgorithmParameters(AbstractSCCKey key, byte[] nonce, int tag, String algo) {
		super(key, nonce, tag, algo);
	}

	// for asymmetric
	SCCAlgorithmParameters(AbstractSCCKeyPair keyPair, String algo) {
		super(keyPair, algo);
	}

	// for signing
	SCCAlgorithmParameters(AbstractSCCKeyPair keyPair, String algo, PlaintextContainerInterface plaintext) {
		super(keyPair, algo, plaintext);
	}

	SCCAlgorithmParameters(HashMap<String, String> params)
	    {
	    	super(params);
	    }
}
