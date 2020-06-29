package main;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class SCCKey extends AbstractSCCKey {

	public enum SCCKeyAlgorithm {
		AES, Blowfish, ARCFOUR, DES, DESede, HmacMD5, HmacSHA1, HmacSHA224, HmacSHA256, HmacSHA384, HmacSHA512, RC2
	}

	public SCCKey(byte[] key, SCCKeyAlgorithm algorithm) {
		super(key, algorithm);
	}

	@Override
	public SecretKey getSecretKey() {
		return new SecretKeySpec(key, 0, key.length, this.algorithm.toString());
	}

	@Override
	public byte[] getByteArray() {
		return this.key;
	}

	@Override
	public String getAlgorithm() {
		return this.algorithm.toString();
	}

}
