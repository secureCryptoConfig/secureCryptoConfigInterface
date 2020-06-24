package main;

import java.nio.charset.StandardCharsets;

import COSE.CoseException;

public class PlaintextContainer implements PlaintextContainerInterface {

	private String plaintext;
	SecureCryptoConfig scc = new SecureCryptoConfig();
	
	public PlaintextContainer(String plaintext) {
		this.plaintext = plaintext;
	}

	@Override
	public byte[] getByteArray() {
		return plaintext.getBytes(StandardCharsets.UTF_8);
	}

	@Override
	public String getString() {
		return this.plaintext;
	}

	@Override
	public boolean verifyHash(SCCHash hash) {
		try {
			return scc.verifyHash(this, hash);
		} catch (CoseException e) {
			e.printStackTrace();
			return false;
		}
	}


}
