package main;

import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class SCCKey extends main.AbstractSCCKey {

	private static final long serialVersionUID = 1L;

	protected SCCKey(byte[] key, String algorithm) {
		super(key, algorithm);
		// TODO Auto-generated constructor stub
	}

	@Override
	public SCCKey createKey(byte[] bytes) {
		// TODO Auto-generated method stub
		return null;
	}

	public static SCCKey createKey() {
		KeyGenerator keyGen;
		try {
			keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(256);
			SecretKey key = keyGen.generateKey();
			return new SCCKey(key.getEncoded(), "AES");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;

	}

	@Override
	SCCKeyType getSCCKeyType() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	String getDefaultAlgorithm() {
		// TODO Auto-generated method stub
		return null;
	}

}
