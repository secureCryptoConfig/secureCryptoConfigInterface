package org.securecryptoconfig;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import org.junit.jupiter.api.Test;
import org.securecryptoconfig.SCCKey.KeyUseCase;
import org.securecryptoconfig.SecureCryptoConfig.SCCAlgorithm;

import COSE.CoseException;

/**
 * Class for testing all functionalities for asymmetric encryption from the
 * Secure Crypto Config Interface
 * 
 * @author Lisa
 *
 */
class TestAsymmetricEncryption {

	SecureCryptoConfig scc = new SecureCryptoConfig();

	// Use Cases:
	// asymmetric encryption:
	// - byte[] encrypt, return: encrypted byte[] + new key
	// - String encrypt, return: encrypted String + new key

	// - byte[] encrypt + key, return: encrypted byte[]
	// - String encrypt + key, return: encrypted String

	// asymmetric decryption:
	// - encrypted byte[] decrypt + key, return: decrypted byte[]
	// - encrypted String decrypt + key, return: decrypted String

	// asymmetric ReEncrypt
	// - encrypted byte[] encrypt + key, return: encrypted byte[]
	// - encrypted String encrypt + key, return: encrypted String

	// - byte[] encrypt, return: encrypted byte[] + new key
	// - encrypted byte[] decrypt + key, return: decrypted byte[]
	@Test
	void testAymmetricByteDecryptWithKey()
			throws CoseException, NoSuchAlgorithmException, InvalidKeyException, SCCException {
		byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
		SCCKey key = SCCKey.createKey(KeyUseCase.AsymmetricEncryption);
		// Encryption
		SCCCiphertext ciphertext = scc.encryptAsymmetric(key, plaintext);
		// Decryption
		PlaintextContainer plain = ciphertext.decryptAsymmetric(key);
		byte[] decrypted = plain.toBytes();

		assertEquals(new String(plaintext, StandardCharsets.UTF_8), plain.toString(StandardCharsets.UTF_8));
	}

	// - String encrypt, return: encrypted String + new key
	// - encrypted String decrypt + key, return: decrypted String
	@Test
	void testAsymmetricStringDecryptWithKey()
			throws CoseException, NoSuchAlgorithmException, InvalidKeyException, SCCException {
		String plaintext = "Hello World!";
		SCCKey key = SCCKey.createKey(KeyUseCase.AsymmetricEncryption);
		// Encryption
		SCCCiphertext ciphertext = scc.encryptAsymmetric(key, plaintext.getBytes(StandardCharsets.UTF_8));
		// Decryption
		PlaintextContainer decryptedCiphertext = ciphertext.decryptAsymmetric(key);
		String decrypted = decryptedCiphertext.toString(StandardCharsets.UTF_8);

		assertEquals(plaintext, decrypted);

	}

	// - byte[] encrypt + key, return: encrypted byte[]
	@Test
	void testAsymmetricByteEncryptionWithExistingKey()
			throws NoSuchAlgorithmException, CoseException, InvalidKeyException, SCCException {
		// SCCKey already exists
		SCCKey existingKey = SCCKey.createKey(KeyUseCase.AsymmetricEncryption);
		byte[] existingSCCKey = existingKey.decodeObjectToBytes();

		// Convert existing byte[] to SCCKey
		SCCKey key = SCCKey.createFromExistingKey(existingSCCKey);
		byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
		SCCCiphertext ciphertext = scc.encryptAsymmetric(key, plaintext);
		byte[] encrypted = ciphertext.toBytes();

		PlaintextContainer plain = ciphertext.decryptAsymmetric(key);
		byte[] decrypted = plain.toBytes();

		assertEquals(new String(plaintext, StandardCharsets.UTF_8), plain.toString(StandardCharsets.UTF_8));

	}

	// - String encrypt + key, return: encrypted String
	@Test
	void testAsymmetricStringEncryptionWithExistingKey()
			throws NoSuchAlgorithmException, CoseException, InvalidKeyException, SCCException {

		// SCCKey already exists
		SCCKey existingKey = SCCKey.createKey(KeyUseCase.AsymmetricEncryption);
		byte[] existingSCCKey = existingKey.decodeObjectToBytes();

		// Convert existing byte[] to SCCKey
		SCCKey key = SCCKey.createFromExistingKey(existingSCCKey);

		String plaintext = "Hello World!";
		SCCCiphertext ciphertext = scc.encryptAsymmetric(key, plaintext.getBytes(StandardCharsets.UTF_8));
		String encrypted = ciphertext.toBase64();

		PlaintextContainer decryptedCiphertext = ciphertext.decryptAsymmetric(key);
		String decrypted = decryptedCiphertext.toString(StandardCharsets.UTF_8);

		assertEquals(plaintext, decrypted);
	}

	// - encrypted byte[] encrypt + key, return: encrypted byte[]
	@Test
	void testAsymmetricByteReEncyptionWithKey()
			throws CoseException, NoSuchAlgorithmException, InvalidKeyException, SCCException {
		byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
		SCCKey key = SCCKey.createKey(KeyUseCase.AsymmetricEncryption);
		// Encryption
		SCCCiphertext ciphertext = scc.encryptAsymmetric(key, plaintext);
		// ReEncryption
		SCCCiphertext updatedCiphertext = scc.reEncryptAsymmetric(key, ciphertext);
		byte[] updateCiphertect = updatedCiphertext.toBytes();

		String oldCiphertext = ciphertext.toBase64();
		String newCiphertext = updatedCiphertext.toBase64();

		assertNotEquals(oldCiphertext, newCiphertext);
	}

	// - encrypted String encrypt + key, return: encrypted String
	@Test
	void testAsymmetricStringReEncyptionWithKey()
			throws CoseException, NoSuchAlgorithmException, InvalidKeyException, SCCException {
		String plaintext = "Hello World!";
		SCCKey key = SCCKey.createKey(KeyUseCase.AsymmetricEncryption);
		// Encryption
		SCCCiphertext ciphertext = scc.encryptAsymmetric(key, plaintext.getBytes(StandardCharsets.UTF_8));
		// ReEncryption
		SCCCiphertext updatedCiphertext = scc.reEncryptAsymmetric(key, ciphertext);
		String updateCiphertext = updatedCiphertext.toBase64();

		String oldCiphertext = ciphertext.toBase64();
		String newCiphertext = updatedCiphertext.toBase64();

		assertNotEquals(oldCiphertext, newCiphertext);

	}

	@Test
	void testAsymmetricEncryptionWithSpecificAlgo() throws SCCException {
		// Set specific algorithm
		SecureCryptoConfig.setAlgorithm(SCCAlgorithm.RSA_SHA_256);

		String plaintext = "Hello World!";
		SCCKey key = SCCKey.createKey(KeyUseCase.AsymmetricEncryption);
		// Encryption
		SCCCiphertext ciphertext = scc.encryptAsymmetric(key, plaintext.getBytes(StandardCharsets.UTF_8));
		// Decryption
		PlaintextContainer decryptedCiphertext = ciphertext.decryptAsymmetric(key);
		String decrypted = decryptedCiphertext.toString(StandardCharsets.UTF_8);

		assertEquals(plaintext, decrypted);
		SecureCryptoConfig.defaultAlgorithm();
	}

	@Test
	void testAsymmetricEncryptionWithWrongAlgo() throws SCCException {

		String plaintext = "Hello World!";
		SCCKey key = SCCKey.createKey(KeyUseCase.AsymmetricEncryption);

		// Set specific algorithm
		SecureCryptoConfig.setAlgorithm(SCCAlgorithm.ECDSA_256);

		// Encryption
		assertThrows(SCCException.class, () -> scc.encryptAsymmetric(key, plaintext.getBytes(StandardCharsets.UTF_8)));

		SecureCryptoConfig.defaultAlgorithm();
	}

}
