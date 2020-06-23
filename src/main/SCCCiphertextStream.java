package main;

import java.io.OutputStream;

import javax.crypto.Cipher;

public class SCCCiphertextStream extends AbstractSCCCiphertextStream{

	public SCCCiphertextStream(OutputStream os, Cipher c, SCCAlgorithmParameters param) {
		super(os, c, param);
	}

}
