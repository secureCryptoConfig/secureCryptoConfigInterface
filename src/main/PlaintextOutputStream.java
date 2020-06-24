package main;

import java.io.InputStream;

import javax.crypto.Cipher;

public class PlaintextOutputStream extends AbstractPlaintextOutputStream{

	public PlaintextOutputStream(InputStream is, Cipher c) {
		super(is, c);
	}

	
	
}
