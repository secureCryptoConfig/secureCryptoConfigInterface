package test;

import static org.junit.jupiter.api.Assertions.*;

import java.security.NoSuchAlgorithmException;

import javax.crypto.SecretKey;

import main.UseCases;

import org.junit.jupiter.api.Test;

class SecureCryptoConfigTest {

	UseCases s = new UseCases();
	String plainText ="Hello World";
	
	//Test for basic symmetric en/decryption
	@Test
	void testSymmetricEncryption() throws NoSuchAlgorithmException {
		SecretKey key = UseCases.makeKey();
		byte[] nonce = UseCases.generateNonce(32);
		byte[] plain  = UseCases.getByte(plainText);
		String cipherText = s.symmetricEncrypt(key, plain, nonce);
		String decrypted = s.symmetricDecrypt(key, cipherText, nonce);

		assertEquals(plainText, decrypted);
	}
	
	//Test for Hashing / how to test?
	@Test
	void testHashing()  {
		String hashed1 = s.hash(plainText);
		String hashed2 = s.hash(plainText);
		assertEquals(hashed1, hashed2);
	}

}
