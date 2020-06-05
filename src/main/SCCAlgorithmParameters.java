package main;

public class SCCAlgorithmParameters extends AbstractSCCAlgorithmParameters {

	//for symmetric
	SCCAlgorithmParameters(AbstractSCCKey key, byte[] nonce, int tag, String algo) {
		super(key, nonce, tag, algo);
	}
	
	//for asymmetric
	SCCAlgorithmParameters(AbstractSCCKey[] keyPair, String algo) {
		super(keyPair, algo);
	}

}
