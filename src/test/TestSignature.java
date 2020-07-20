package test;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import org.junit.jupiter.api.Test;
import org.securecryptoconfig.SCCException;
import org.securecryptoconfig.SCCKey;
import org.securecryptoconfig.SCCKey.KeyUseCase;
import org.securecryptoconfig.SCCSignature;
import org.securecryptoconfig.SecureCryptoConfig;

import COSE.CoseException;

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
	void testSigningByteValidation() throws CoseException, NoSuchAlgorithmException, InvalidKeyException, SCCException {
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
			throws CoseException, NoSuchAlgorithmException, InvalidKeyException, SCCException {
		String plaintext = "Hello World!";
		SCCKey pair = SCCKey.createKey(KeyUseCase.Signing);

		SCCSignature signature = scc.sign(pair, plaintext.getBytes(StandardCharsets.UTF_8));

		assertTrue(scc.validateSignature(pair, signature));
	}

	// - signature + key, return: updated byte[] signature
	@Test
	void testUpdateSigningByte() throws CoseException, NoSuchAlgorithmException, InvalidKeyException, SCCException {
		byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
		SCCKey pair = SCCKey.createKey(KeyUseCase.Signing);

		SCCSignature oldSignature = scc.sign(pair, plaintext);
		byte[] oldSignaturebytes = oldSignature.toBytes();

		SCCSignature newSignature = scc.updateSignature(pair, plaintext);
		byte[] newSignatureBytes = newSignature.toBytes();

		assertTrue(scc.validateSignature(pair, oldSignature));
		assertTrue(scc.validateSignature(pair, new SCCSignature(oldSignaturebytes)));

		assertTrue(scc.validateSignature(pair, newSignature));
		assertTrue(scc.validateSignature(pair, new SCCSignature(newSignatureBytes)));

	}

	// - signature + key, return: updated String signature
	@Test
	void testUpdateSigningString() throws CoseException, NoSuchAlgorithmException, InvalidKeyException, SCCException {
		String plaintext = "Hello World!";
		SCCKey pair = SCCKey.createKey(KeyUseCase.Signing);

		SCCSignature oldSignature = scc.sign(pair, plaintext.getBytes(StandardCharsets.UTF_8));
		String oldSignatureString = oldSignature.toString();

		SCCSignature newSignature = scc.updateSignature(pair, plaintext.getBytes());
		String newSignatureString = newSignature.toString();

		assertTrue(scc.validateSignature(pair, oldSignature));
		assertTrue(scc.validateSignature(pair, new SCCSignature(oldSignatureString)));

		assertTrue(scc.validateSignature(pair, newSignature));
		assertTrue(scc.validateSignature(pair, new SCCSignature(newSignatureString)));
	}

}
