package test;

import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import org.junit.jupiter.api.Test;

import COSE.CoseException;
import main.PlaintextContainer;
import main.SCCCiphertext;
import main.SCCKeyPair;
import main.SCCKeyPair.keyPairUseCase;
import main.SecureCryptoConfig;

class TestAsymmetricEncryption {

	SecureCryptoConfig scc = new SecureCryptoConfig();
	String filepath = ".\\src\\main\\Test.txt";

	// Use Cases:
	// TODO RFC use cases
	// encryption:
	// - byte[] encrypt, return: encrypted byte[] + new key
	// - String encrypt, return: encrypted String + new key

	// - byte[] encrypt + key, return: encrypted byte[]
	// - String encrypt + key, return: encrypted String

	// decryption:
	// - encrypted byte[] decrypt + key, return: decrypted byte[]
	// - encrypted String decrypt + key, return: decrypted String

	// ReEncrypt
	// - encrypted byte[] encrypt + key, return: encrypted byte[]
	// - encrypted String encrypt + key, return: encrypted String

	/**
	 * Testing of asymmetric Encryption/Decryption
	 */

	// - byte[] encrypt, return: encrypted byte[] + new key
	@Test
	void testAsymmetricByteEncryptNoExistingKey() throws CoseException, NoSuchAlgorithmException {
		byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
		SCCKeyPair pair = SCCKeyPair.createKeyPair(keyPairUseCase.AsymmetricEncryption);
		SCCCiphertext ciphertext = scc.asymmetricEncrypt(pair, plaintext);
		byte[] encrypted = ciphertext.getCiphertextBytes();

		assertTrue(encrypted instanceof byte[]);
		assertTrue(pair instanceof SCCKeyPair);

	}

	// - String encrypt, return: encrypted String + new key
	@Test
	void testAsymmetricStringEncryptNoExistingKey() throws CoseException, NoSuchAlgorithmException {
		String plaintext = "Hello World!";
		SCCKeyPair pair = SCCKeyPair.createKeyPair(keyPairUseCase.AsymmetricEncryption);
		SCCCiphertext ciphertext = scc.asymmetricEncrypt(pair, plaintext.getBytes(StandardCharsets.UTF_8));
		String encrypted = ciphertext.getCiphertextAsString(StandardCharsets.UTF_8);

		assertTrue(encrypted instanceof String);
		assertTrue(pair instanceof SCCKeyPair);
	}

	// - byte[] encrypt + key, return: encrypted byte[]
	@Test
	void testAsymmetricByteEncryptionWithExistingKey() throws NoSuchAlgorithmException, CoseException {
		// KeyPair already exists
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(4096);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();

		// Convert existing pair to SCCKeyPair
		SCCKeyPair pair = new SCCKeyPair(keyPair);

		byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
		SCCCiphertext ciphertext = scc.asymmetricEncrypt(pair, plaintext);
		byte[] encrypted = ciphertext.getCiphertextBytes();

		assertTrue(encrypted instanceof byte[]);
	}

	// - String encrypt + key, return: encrypted String
	@Test
	void testAsymmetricStringEncryptionWithExistingKey() throws NoSuchAlgorithmException, CoseException {
		// KeyPair already exists
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(4096);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();

		// Convert existing pair to SCCKeyPair
		SCCKeyPair pair = new SCCKeyPair(keyPair);

		String plaintext = "Hello World!";
		SCCCiphertext ciphertext = scc.asymmetricEncrypt(pair, plaintext.getBytes(StandardCharsets.UTF_8));
		String encrypted = ciphertext.getCiphertextAsString(StandardCharsets.UTF_8);

		assertTrue(encrypted instanceof String);
	}

	// - encrypted byte[] decrypt + key, return: decrypted byte[]
	@Test
	void testAymmetricByteDecryptWithKey() throws CoseException, NoSuchAlgorithmException {
		byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
		SCCKeyPair pair = SCCKeyPair.createKeyPair(keyPairUseCase.AsymmetricEncryption);
		// Encryption
		SCCCiphertext ciphertext = scc.asymmetricEncrypt(pair, plaintext);
		// Decryption
		PlaintextContainer plain = ciphertext.asymmetricDecrypt(pair);
		byte[] decrypted = plain.getPlaintextBytes();

		assertEquals(new String(plaintext, StandardCharsets.UTF_8), plain.getPlaintextAsString(StandardCharsets.UTF_8));
	}

	// - encrypted String decrypt + key, return: decrypted String
	@Test
	void testAsymmetricStringDecryptWithKey() throws CoseException, NoSuchAlgorithmException {
		String plaintext = "Hello World!";
		SCCKeyPair pair = SCCKeyPair.createKeyPair(keyPairUseCase.AsymmetricEncryption);
		// Encryption
		SCCCiphertext ciphertext = scc.asymmetricEncrypt(pair, plaintext.getBytes(StandardCharsets.UTF_8));
		// Decryption
		PlaintextContainer decryptedCiphertext = ciphertext.asymmetricDecrypt(pair);
		String decrypted = decryptedCiphertext.getPlaintextAsString(StandardCharsets.UTF_8);

		assertEquals(plaintext, decrypted);

	}


	// - encrypted byte[] encrypt + key, return: encrypted byte[]
	@Test
	void testAsymmetricByteReEncyptionWithKey() throws CoseException, NoSuchAlgorithmException {
		byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
		SCCKeyPair pair = SCCKeyPair.createKeyPair(keyPairUseCase.AsymmetricEncryption);
		// Encryption
		SCCCiphertext ciphertext = scc.asymmetricEncrypt(pair, plaintext);
		// ReEncryption
		SCCCiphertext updatedCiphertext = scc.asymmetricReEncrypt(pair, ciphertext);
		byte[] updateCiphertext = updatedCiphertext.getCiphertextBytes();

		String oldCiphertext = ciphertext.getCiphertextAsString(StandardCharsets.UTF_8);
		String newCiphertext = updatedCiphertext.getCiphertextAsString(StandardCharsets.UTF_8);

		assertFalse(oldCiphertext.equals(newCiphertext));
	}

	// - encrypted String encrypt + key, return: encrypted String
	@Test
	void testAsymmetricStringReEncyptionWithKey() throws CoseException, NoSuchAlgorithmException {
		String plaintext = "Hello World!";
		SCCKeyPair pair = SCCKeyPair.createKeyPair(keyPairUseCase.AsymmetricEncryption);
		// Encryption
		SCCCiphertext ciphertext = scc.asymmetricEncrypt(pair, plaintext.getBytes(StandardCharsets.UTF_8));
		// ReEncryption
		SCCCiphertext updatedCiphertext = scc.asymmetricReEncrypt(pair, ciphertext);
		String updateCiphertext = updatedCiphertext.getCiphertextAsString(StandardCharsets.UTF_8);

		String oldCiphertext = ciphertext.getCiphertextAsString(StandardCharsets.UTF_8);
		String newCiphertext = updatedCiphertext.getCiphertextAsString(StandardCharsets.UTF_8);

		assertFalse(oldCiphertext.equals(newCiphertext));
	}


}