package test;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.security.NoSuchAlgorithmException;

import javax.crypto.SecretKey;

import org.junit.jupiter.api.Test;

import main.PlaintextContainer;
import main.SCCCiphertext;
import main.SCCKey;
import main.SecureCryptoConfig;
import main.UseCases;

class SecureCryptoConfigTest {

	UseCases s = new UseCases();
	String plainText = "Hello World";

	// Test for basic symmetric en/decryption
	@Test
	void testSymmetricEncryption() throws NoSuchAlgorithmException {
		SecretKey key = UseCases.makeKey();
		byte[] nonce = UseCases.generateNonce(32);
		byte[] plain = UseCases.getByte(plainText);
		String cipherText = s.symmetricEncrypt(key, plain, nonce);
		String decrypted = s.symmetricDecrypt(key, cipherText, nonce);

		assertEquals(plainText, decrypted);
	}

	@Test
	void testSCCsymmetricEncryption() {
		SecureCryptoConfig scc = new SecureCryptoConfig();
		String inputPlaintext = "very confidential";
		PlaintextContainer plaintextContainer = new PlaintextContainer(inputPlaintext);
		SCCKey scckey = SCCKey.createKey();
		SCCCiphertext sccciphertext = scc.symmetricEncrypt(scckey, plaintextContainer);
		String encryptedPlaintext = sccciphertext.toString();

		PlaintextContainer outputPlaintext = scc.symmetricDecrypt(scckey, sccciphertext);

		// TODO compare decrypted to original plaintext

	}

	// Test for Hashing / how to test?
	@Test
	void testHashing() {
		String hashed1 = s.hash(plainText);
		String hashed2 = s.hash(plainText);
		assertEquals(hashed1, hashed2);
	}

}
