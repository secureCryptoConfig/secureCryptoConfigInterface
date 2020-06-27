package main;

import java.nio.charset.Charset;
import java.util.Base64;

import COSE.CoseException;

public class PlaintextContainer implements PlaintextContainerInterface {

	private byte[] plaintext;
	SecureCryptoConfig scc = new SecureCryptoConfig();
	
	public PlaintextContainer(byte[] plaintext) {
		this.plaintext = plaintext;
	}
	

	@Override
	public byte[] getByteArray() {
		return plaintext;
	}

	@Override
	public String getBase64() {
		return Base64.getEncoder().encodeToString(this.plaintext);

	}
	
	@Override
	public String getString(Charset c) {
		return new String(this.plaintext, c);

	}

	@Override
	public boolean verifyHash(SCCHash hash) {
		try {
			return scc.validateHash(this, hash);
		} catch (CoseException e) {
			e.printStackTrace();
			return false;
		}
	}


}
