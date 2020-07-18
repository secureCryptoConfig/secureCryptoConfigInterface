package test;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import org.junit.jupiter.api.Test;

import COSE.CoseException;
import main.SCCKey;
import main.SCCKey.KeyUseCase;
import main.SCCSignature;
import main.SecureCryptoConfig;

class TestSignature {

	SecureCryptoConfig scc = new SecureCryptoConfig();

	// Use Cases:
	// Signature
	// - byte[] plain sign, return: byte[] signature + new key
	// - String plain sign, return: String signature + new key

	// - byte[] plain sign + validate, return: boolean
	// - String plain sign + validate, return: boolean

	// - signature + key, return: updated byte[] signature
	// - signature + key, return: updated String signature

	// - byte[] plain sign, return: byte[] signature + new key
	// - byte[] plain sign + validate, return: boolean
	@Test
	void testSigningByteValidation()
			throws CoseException, NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException {
		byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
		SCCKey pair = SCCKey.createKey(KeyUseCase.Signing);

		SCCSignature signature = scc.sign(pair, plaintext);

		boolean result = scc.validateSignature(pair, signature);

		assertTrue(result);

	}

	// - String plain sign, return: String signature + new key
	// - String plain sign + validate, return: boolean
	@Test
	void testSigningStringValidation()
			throws CoseException, NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException {
		String plaintext = "Hello World!";
		SCCKey pair = SCCKey.createKey(KeyUseCase.Signing);

		SCCSignature signature = scc.sign(pair, plaintext.getBytes(StandardCharsets.UTF_8));

		boolean result = scc.validateSignature(pair, signature);

		assertTrue(result);

	}

	// - signature + key, return: updated byte[] signature
	@Test
	void testUpdateSigningByte()
			throws CoseException, NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException {
		byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
		SCCKey pair = SCCKey.createKey(KeyUseCase.Signing);

		SCCSignature oldSignature = scc.sign(pair, plaintext);

		SCCSignature updatedSignature = scc.updateSignature(pair, plaintext);
		byte[] newSignature = updatedSignature.toBytes();

		assertTrue(newSignature instanceof byte[]);

	}

	// - signature + key, return: updated String signature
	@Test
	void testUpdateSigningString()
			throws CoseException, NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException {
		String plaintext = "Hello World!";
		SCCKey pair = SCCKey.createKey(KeyUseCase.Signing);

		SCCSignature oldSignature = scc.sign(pair, plaintext.getBytes(StandardCharsets.UTF_8));

		SCCSignature updatedSignature = scc.updateSignature(pair, plaintext.getBytes());
		String newSignature = updatedSignature.toString(StandardCharsets.UTF_8);

		assertTrue(newSignature instanceof String);
	}

}
