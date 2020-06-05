package test;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.security.NoSuchAlgorithmException;

import javax.crypto.SecretKey;

import org.junit.jupiter.api.Test;

import main.PlaintextContainer;
import main.SCCCiphertext;
import main.SCCHash;
import main.SCCKey;
import main.SecureCryptoConfig;
import main.UseCases;

class SecureCryptoConfigTest {

	SecureCryptoConfig scc = new SecureCryptoConfig();
	String inputPlaintext = "very confidential";
	PlaintextContainer plaintextContainer = new PlaintextContainer(inputPlaintext);

	//@Test
	void testSCCsymmetricEncryption() {
		SCCKey scckey = SCCKey.createKey();

		SCCCiphertext sccciphertext = scc.symmetricEncrypt(scckey, plaintextContainer);
		//String encryptedPlaintext = sccciphertext.toString();
		PlaintextContainer plain = scc.symmetricDecrypt(scckey, sccciphertext);
		String decrypted = plain.getPlain();
		assertEquals(inputPlaintext, decrypted);

	}

	// Test for Hashing / how to test?
	@Test
	void testHashing() {
		SCCHash hashed = scc.hash(plaintextContainer);
		String s = hashed.toString();
		SCCHash hashed1 = scc.hash(plaintextContainer);
		String s1 = hashed1.toString();
		assertEquals(s, s1);
	}

}
