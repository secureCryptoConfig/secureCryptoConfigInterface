package org.securecryptoconfig;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.securecryptoconfig.SCCKey.KeyUseCase;

import COSE.CoseException;

class TestPlaintextContainer {

	static SecureCryptoConfig scc;
	static String plaintext;
	static PlaintextContainer pc;
	static SCCKey symmetricKey;
	static SCCKey asymmetricKey;
	static SCCKey signingKey;

	@BeforeAll
	static void setup() throws SCCException, CoseException {
		scc = new SecureCryptoConfig();
		plaintext = "Hello World!";
		pc = new PlaintextContainer(plaintext.getBytes(StandardCharsets.UTF_8));
		symmetricKey = SCCKey.createSymmetricKeyWithPassword("password".getBytes(StandardCharsets.UTF_8));
		asymmetricKey = SCCKey.createKey(KeyUseCase.AsymmetricEncryption);
		signingKey = SCCKey.createKey(KeyUseCase.Signing);
	}

	@Test
	void testValidateHash() throws SCCException {
		assertTrue(pc.validateHash(pc.hash()));
	}

	@Test
	void testValidatePasswordHash() throws SCCException {
		assertTrue(pc.validatePasswordHash(pc.passwordHash()));
	}

	@Test
	void testEncryptSymmetric() throws SCCException {
		SCCCiphertext ciphertext = pc.encryptSymmetric(symmetricKey);
		String otherPlaintext = ciphertext.decryptSymmetric(symmetricKey).toString(StandardCharsets.UTF_8);
		assertEquals(plaintext, otherPlaintext);
	}

	@Test
	void testEncryptAsymmetric() throws SCCException {
		SCCCiphertext ciphertext = pc.encryptAsymmetric(asymmetricKey);
		String otherPlaintext = ciphertext.decryptAsymmetric(asymmetricKey).toString(StandardCharsets.UTF_8);
		assertEquals(plaintext, otherPlaintext);
	}

	@Test
	void testSign() throws SCCException {
		SCCSignature signature = pc.sign(signingKey);

		String otherPlaintext = "Hello Malory!";
		PlaintextContainer otherPc = new PlaintextContainer(otherPlaintext.getBytes(StandardCharsets.UTF_8));
		SCCSignature otherSignature = otherPc.sign(signingKey);

		assertNotEquals(signature.toBase64(), otherSignature.toBase64());
	}

	@Test
	void testValidateSignature() throws SCCException {
		SCCSignature s = pc.sign(signingKey);
		assertTrue(pc.validateSignature(s, signingKey));

		String otherPlaintext = "Hello Malory!";
		PlaintextContainer otherPc = new PlaintextContainer(otherPlaintext.getBytes(StandardCharsets.UTF_8));
		assertFalse(otherPc.validateSignature(s, signingKey));

	}
}
