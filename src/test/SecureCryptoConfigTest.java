package test;

import static org.junit.jupiter.api.Assertions.assertEquals;


import org.junit.jupiter.api.Test;

import main.PlaintextContainer;
import main.SCCCiphertext;
import main.SCCHash;
import main.SCCKey;
import main.SCCKeyPair;
import main.SCCSignature;
import main.SecureCryptoConfig;

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
	//@Test
	void testHashing() {
		SCCHash hashed = scc.hash(plaintextContainer);
		String s = hashed.toString();
		SCCHash hashed1 = scc.hash(plaintextContainer);
		String s1 = hashed1.toString();
		assertEquals(s, s1);
	}
	
	//@Test
	void testSCCasymmetricEncryption(){
		SCCKeyPair pair = SCCKeyPair.createKeyPair();
		SCCCiphertext encrypted = scc.asymmetricEncrypt(pair, plaintextContainer);
		PlaintextContainer decrypted = scc.asymmetricDecrypt(pair, encrypted);
		assertEquals(inputPlaintext,decrypted.getPlain());
	}
	
	@Test
	void testSCCSignature(){
		SCCKeyPair pair = SCCKeyPair.createKeyPair();
		SCCSignature s = scc.sign(pair, plaintextContainer);
		assertEquals(true, scc.validateSignature(pair, s));
	}
	

}
