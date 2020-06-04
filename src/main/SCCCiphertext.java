package main;

public class SCCCiphertext extends AbstractSCCCiphertext {

	byte[] ciphertext;
	SCCAlgorithmParameters parameters;

	private SCCCiphertext SCCCiphertext() {
		return SCCCiphertext(new String("empty").getBytes(), new SCCAlgorithmParameters());
	}

	public static SCCCiphertext getSCCCiphertext() {
		return new SCCCiphertext();
	}

	@Override
	public SCCCiphertext SCCCiphertext(byte[] ciphertext, SCCAlgorithmParameters parameters) {
		// TODO Auto-generated method stub
		this.ciphertext = ciphertext;
		this.parameters = parameters;
		return this;
	}

	@Override
	AbstractAlgorithmIdentifier getAlgorithmIdentifier(SCCCiphertext sccciphertext) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String toString() {
		// TODO Auto-generated method stub
		return new String(this.ciphertext);
	}

}
