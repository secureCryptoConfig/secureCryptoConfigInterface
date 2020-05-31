package test;

import static org.junit.jupiter.api.Assertions.*;

import java.security.NoSuchAlgorithmException;

import javax.crypto.SecretKey;

import main.SymmetricEncryption;

import org.junit.jupiter.api.Test;

class SecureCryptoConfigTest {

	SymmetricEncryption s = new SymmetricEncryption();
	String plainText ="Hello World";
	
	@Test
	void testSymmetricEncryption() throws NoSuchAlgorithmException {
		SecretKey key = s.makeKey();
		byte[] nonce = s.generateNonce(32);
		byte[] plain  = s.getByte(plainText);
		String cipherText = s.encrypt(key, plain, nonce);
		String decrypted = s.decrypt(key, cipherText, nonce);

		assertEquals(plainText, decrypted);
	}

}
