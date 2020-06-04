package main;

public class PlaintextContainer implements PlaintextContainerInterface {

	private String plaintext;

	@Override
	public byte[] getPlaintext() {
		// TODO Auto-generated method stub
		return plaintext.getBytes();
	}

	@Override
	public boolean verifyHash(AbstractSCCHash scchash) {
		// TODO Auto-generated method stub
		return false;
	}

	public PlaintextContainer(String plaintext) {
		this.plaintext = plaintext;
	}

}
