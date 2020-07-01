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
import main.SCCKey;
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
		SCCCiphertext cipher = scc.asymmetricEncrypt(pair, new PlaintextContainer(plaintext));
		byte[] encrypted = cipher.getCipherBytes();

		assertTrue(encrypted instanceof byte[]);
		assertTrue(pair instanceof SCCKeyPair);

	}

	// - String encrypt, return: encrypted String + new key
	@Test
	void testAsymmetricStringEncryptNoExistingKey() throws CoseException, NoSuchAlgorithmException {
		String plaintext = "Hello World!";
		SCCKeyPair pair = SCCKeyPair.createKeyPair(keyPairUseCase.AsymmetricEncryption);
		SCCCiphertext cipher = scc.asymmetricEncrypt(pair,
				new PlaintextContainer(plaintext.getBytes(StandardCharsets.UTF_8)));
		String encrypted = cipher.getCipherAsString(StandardCharsets.UTF_8);

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
		SCCCiphertext cipher = scc.asymmetricEncrypt(pair, new PlaintextContainer(plaintext));
		byte[] encrypted = cipher.getCipherBytes();

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
		SCCCiphertext cipher = scc.asymmetricEncrypt(pair, new PlaintextContainer(plaintext.getBytes(StandardCharsets.UTF_8)));
		String encrypted = cipher.getCipherAsString(StandardCharsets.UTF_8);

		assertTrue(encrypted instanceof String);
	}

	// - encrypted byte[] decrypt + key, return: decrypted byte[]
	@Test
	void testAymmetricByteDecryptWithKey() throws CoseException, NoSuchAlgorithmException {
		byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
		SCCKeyPair pair = SCCKeyPair.createKeyPair(keyPairUseCase.AsymmetricEncryption);
		// Encryption
		SCCCiphertext cipher = scc.asymmetricEncrypt(pair, new PlaintextContainer(plaintext));
		// Decryption
		PlaintextContainer plain = cipher.asymmetricDecrypt(pair);
		byte[] decrypted = plain.getByteArray();

		assertEquals(new String(plaintext, StandardCharsets.UTF_8), plain.getString(StandardCharsets.UTF_8));
	}

	// - encrypted String decrypt + key, return: decrypted String
	@Test
	void testAsymmetricStringDecryptWithKey() throws CoseException, NoSuchAlgorithmException {
		String plaintext = "Hello World!";
		SCCKeyPair pair = SCCKeyPair.createKeyPair(keyPairUseCase.AsymmetricEncryption);
		// Encryption
		SCCCiphertext cipher = scc.asymmetricEncrypt(pair, new PlaintextContainer(plaintext.getBytes(StandardCharsets.UTF_8)));
		// Decryption
		PlaintextContainer plain = cipher.asymmetricDecrypt(pair);
		String decrypted = plain.getString(StandardCharsets.UTF_8);

		assertEquals(plaintext, decrypted);

	}


	// - encrypted byte[] encrypt + key, return: encrypted byte[]
	@Test
	void testAsymmetricByteReEncyptionWithKey() throws CoseException, NoSuchAlgorithmException {
		byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
		SCCKeyPair pair = SCCKeyPair.createKeyPair(keyPairUseCase.AsymmetricEncryption);
		// Encryption
		SCCCiphertext cipher = scc.asymmetricEncrypt(pair, new PlaintextContainer(plaintext));
		// ReEncryption
		SCCCiphertext updatedCipher = scc.asymmetricReEncrypt(pair, cipher);
		byte[] updateCipher = updatedCipher.getCipherBytes();

		String oldCipher = cipher.getCipherAsString(StandardCharsets.UTF_8);
		String newCipher = updatedCipher.getCipherAsString(StandardCharsets.UTF_8);

		assertFalse(oldCipher.equals(newCipher));
	}

	// - encrypted String encrypt + key, return: encrypted String
	@Test
	void testAsymmetricStringReEncyptionWithKey() throws CoseException, NoSuchAlgorithmException {
		String plaintext = "Hello World!";
		SCCKeyPair pair = SCCKeyPair.createKeyPair(keyPairUseCase.AsymmetricEncryption);
		// Encryption
		SCCCiphertext cipher = scc.asymmetricEncrypt(pair, new PlaintextContainer(plaintext.getBytes(StandardCharsets.UTF_8)));
		// ReEncryption
		SCCCiphertext updatedCipher = scc.asymmetricReEncrypt(pair, cipher);
		String updateCipher = updatedCipher.getCipherAsString(StandardCharsets.UTF_8);

		String oldCipher = cipher.getCipherAsString(StandardCharsets.UTF_8);
		String newCipher = updatedCipher.getCipherAsString(StandardCharsets.UTF_8);

		assertFalse(oldCipher.equals(newCipher));
	}


}
