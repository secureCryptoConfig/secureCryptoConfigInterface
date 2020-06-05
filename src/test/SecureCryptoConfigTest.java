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
	String plainText = "very confidential";

	@Test
	void testSCCsymmetricEncryption() {
		SecureCryptoConfig scc = new SecureCryptoConfig();
		String inputPlaintext = "very confidential";
		PlaintextContainer plaintextContainer = new PlaintextContainer(inputPlaintext);
		SCCKey scckey = SCCKey.createKey();

		SCCCiphertext sccciphertext = scc.symmetricEncrypt(scckey, plaintextContainer);
		//String encryptedPlaintext = sccciphertext.toString();
		PlaintextContainer plain = scc.symmetricDecrypt(scckey, sccciphertext);
		String decrypted = plain.getPlain();
		assertEquals(inputPlaintext, decrypted);

	}

	// Test for Hashing / how to test?
	// @Test
	void testHashing() {
		String hashed1 = s.hash(plainText);
		String hashed2 = s.hash(plainText);
		assertEquals(hashed1, hashed2);
	}

}
