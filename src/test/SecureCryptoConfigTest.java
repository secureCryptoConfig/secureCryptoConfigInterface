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
		SecretKey key = s.makeKey();
		byte[] nonce = s.generateNonce(32);
		byte[] plain  = s.getByte(plainText);
		String cipherText = s.symmetricEncrypt(key, plain, nonce);
		String decrypted = s.symmetricDecrypt(key, cipherText, nonce);

		assertEquals(plainText, decrypted);
	}
	
	//Test for Hashing / how to test?
	@Test
	void testHashing()  {
		
		//assertEquals(hashed1, hashed2);
	}

}
