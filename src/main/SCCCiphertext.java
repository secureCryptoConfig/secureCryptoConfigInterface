package main;

import java.nio.charset.StandardCharsets;

public class SCCCiphertext extends AbstractSCCCiphertext {

	public SCCCiphertext(byte[] ciphertext, AbstractSCCAlgorithmParameters parameters) {
		super(ciphertext, parameters);
		// TODO Auto-generated constructor stub
	}
	
	/**
	private SCCCiphertext generateSCCCiphertext() {
		//return SCCCiphertext(new String("empty").getBytes(), new SCCAlgorithmParameters());
		SCCCiphertext c = new SCCCiphertext(new String("empty").getBytes(), new SCCAlgorithmParameters(null, 0, 0, null));
		return c;
	}
	**/

	public static SCCCiphertext getSCCCiphertext() {
		//return new SCCCiphertext();
		SCCCiphertext c = new SCCCiphertext(new String("empty").getBytes(), new SCCAlgorithmParameters(null, 0, 0, null));
		return c;
	}

	
	public SCCCiphertext sCCCiphertext(byte[] ciphertext, SCCAlgorithmParameters parameters) {
		// TODO Auto-generated method stub
		this.ciphertext = ciphertext;
		this.parameters = parameters;
		return this;
	}


	@Override
	public String toString() {
		// TODO Auto-generated method stub
		return new String(this.ciphertext, StandardCharsets.UTF_8);
	}



	@Override
	AbstractAlgorithmIdentifier getAlgorithmIdentifier(AbstractSCCCiphertext sccciphertext) {
		// TODO Auto-generated method stub
		return null;
	}


}
