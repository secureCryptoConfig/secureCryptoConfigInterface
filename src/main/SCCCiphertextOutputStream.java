package main;

import java.io.OutputStream;

import javax.crypto.Cipher;

public class SCCCiphertextOutputStream extends AbstractSCCCiphertextOutputStream{

	public SCCCiphertextOutputStream(OutputStream os, Cipher c, SCCAlgorithmParameters param) {
		super(os, c, param);
	}

}
