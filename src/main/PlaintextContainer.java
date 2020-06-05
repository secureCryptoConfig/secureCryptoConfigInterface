package main;

import java.nio.charset.StandardCharsets;

public class PlaintextContainer implements PlaintextContainerInterface {

	private String plaintext;

	@Override
	public byte[] getByteArray() {
		// TODO Auto-generated method stub
		return plaintext.getBytes(StandardCharsets.UTF_8);
	}

	@Override
	public boolean verifyHash(AbstractSCCHash scchash) {
		// TODO Auto-generated method stub
		return false;
	}

	public PlaintextContainer(String plaintext) {
		this.plaintext = plaintext;
	}
	
	@Override
	public String getPlain()
	{
		return this.plaintext;
	}

}
