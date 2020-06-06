package main;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

public class SCCKeyPair extends AbstractSCCKeyPair {

	protected SCCKeyPair(Key publicKey, Key privateKey, String algorithm) {
		super(publicKey, privateKey, algorithm);
	}

	public Key getPublic()
	{
		return this.publicKey;
	}
	public static SCCKeyPair createKeyPair() {
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(4096);
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			SCCKeyPair pair = new SCCKeyPair(keyPair.getPublic(), keyPair.getPrivate(), "RSA");
			Key p=keyPair.getPublic();
			return pair;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return null;

	}

}
