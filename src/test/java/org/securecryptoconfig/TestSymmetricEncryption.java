package org.securecryptoconfig;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.securecryptoconfig.SCCKey.KeyUseCase;
import COSE.CoseException;

class TestSymmetricEncryption {

	/**
	 * Class for testing all functionalities for symmetric encryption from the Secure Crypto Config Interface
	 * @author Lisa
	 *
	 */
	SecureCryptoConfig scc = new SecureCryptoConfig();

	// Use Cases:
	// encryption:
	// - byte[] encrypt, return: encrypted byte[] + new key
	// - byte[] encrypt + password, return: encrypted byte[] + new key
	// - String encrypt, return: encrypted String + new key
	// - String encrypt + password, return: encrypted String + new key

	// - byte[] encrypt + key, return: encrypted byte[]
	// - String encrypt + key, return: encrypted String

	// - File encrypt, return: File with encrypted content
	// - File decrypt , return: File with decrypted content

	// - File/Stream encrypt, return: encrypting Outputstream + new key
	// - File/Stream encrypt + password, return: encrypting Outputstream
	// - File/Stream encrypt + key, return: encrypting Outputstream

	// decryption:
	// - encrypted byte[] decrypt + key, return: decrypted byte[]
	// - encrypted String decrypt + key, return: decrypted String

	// - encrypted byte[] decrypt + password, return: decrypted byte[]
	// - encrypted String decrypt + password, return: decrypted String

	// - encrypted File/Stream decrypt + password, return: decrypting Inputstream
	// - encrypted File/Stream decrypt + key, return: decrypting Inputstream

	// ReEncrypt
	// - encrypted byte[] encrypt + key, return: encrypted byte[]
	// - encrypted String encrypt + key, return: encrypted String

	// - encrypted File/Stream encrypt + key, return: encrypting Outputstream
	// - encrypted File/Stream encrypt + password, return: encrypting Outputstream

	// - encrypted byte[] encrypt + password, return: encrypted byte[]
	// - encrypted String encrypt + password, return: encrypted String

	/**
	 * Testing of symmetric Encryption/Decryption
	 * 
	 * @throws SCCException
	 */

	// - byte[] encrypt, return: encrypted byte[] + new key
	// - encrypted byte[] decrypt + key, return: decrypted byte[]
	@Test
	void testSymmetricByteDecryptWithKey()
			throws CoseException, NoSuchAlgorithmException, InvalidKeyException, SCCException {
		byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
		SCCKey key = SCCKey.createKey(KeyUseCase.SymmetricEncryption);
		// Encryption
		SCCCiphertext ciphertext = scc.encryptSymmetric(key, plaintext);

		assertNotEquals(Base64.getEncoder().encodeToString(plaintext), ciphertext.toBase64());
		assertNotEquals(0, ciphertext.toBytes().length);

		// Decryption
		PlaintextContainer plain = scc.decryptSymmetric(key, ciphertext);
		byte[] decrypted = plain.toBytes();

		assertEquals(new String(plaintext, StandardCharsets.UTF_8), plain.toString(StandardCharsets.UTF_8));
	}

	// - String encrypt, return: encrypted String + new key
	// - encrypted String decrypt + key, return: decrypted String
	@Test
	void testSymmetricStringDecryptWithKey()
			throws CoseException, NoSuchAlgorithmException, InvalidKeyException, SCCException {
		String plaintext = "Hello World!";
		SCCKey key = SCCKey.createKey(KeyUseCase.SymmetricEncryption);
		// Encryption
		SCCCiphertext ciphertext = scc.encryptSymmetric(key, plaintext.getBytes(StandardCharsets.UTF_8));
		// Decryption
		PlaintextContainer plain = ciphertext.decryptSymmetric(key);
		String decrypted = plain.toString(StandardCharsets.UTF_8);

		assertEquals(plaintext, decrypted);

	}

	// - byte[] encrypt + password, return: encrypted byte[] + new key
	// - encrypted byte[] decrypt + password, return: decrypted byte[]
	@Test
	void testSymmetricByteDecryptWithPassword() throws CoseException, InvalidKeyException, SCCException {
		byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
		byte[] password = "Password!".getBytes(StandardCharsets.UTF_8);
		SCCKey key = SCCKey.createSymmetricKeyWithPassword(password);
		// Encryption
		SCCCiphertext ciphertext = scc.encryptSymmetric(key, plaintext);
		// Decryption
		PlaintextContainer plain = ciphertext.decryptSymmetric(key);
		byte[] decrypted = plain.toBytes();

		assertEquals(new String(plaintext, StandardCharsets.UTF_8), plain.toString(StandardCharsets.UTF_8));

	}

	// - String encrypt + password, return: encrypted String + new key
	// - encrypted String decrypt + password, return: decrypted String
	@Test
	void testSymmetricStringDecryptWithPassword() throws CoseException, InvalidKeyException, SCCException {
		String plaintext = "Hello World!";
		String password = "password";
		SCCKey key = SCCKey.createSymmetricKeyWithPassword(password.getBytes(StandardCharsets.UTF_8));
		// Encryption
		SCCCiphertext ciphertext = scc.encryptSymmetric(key, plaintext.getBytes(StandardCharsets.UTF_8));

		// Decryption
		PlaintextContainer plain = ciphertext.decryptSymmetric(key);
		String decrypted = plain.toString(StandardCharsets.UTF_8);

		assertEquals(plaintext, decrypted);

	}

	// - byte[] encrypt + key, return: encrypted byte[]
	@Test
	void testSymmetricByteEncryptionWithExistingKey()
			throws NoSuchAlgorithmException, CoseException, InvalidKeyException, SCCException {
		// SCCKey already exists
		SCCKey existingKey = SCCKey.createKey(KeyUseCase.SymmetricEncryption);
		byte[] existingSCCKey = existingKey.decodeObjectToBytes();
				
		byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
		SCCKey key = SCCKey.createFromExistingKey(existingSCCKey);
		SCCCiphertext ciphertext = scc.encryptSymmetric(key, plaintext);
		byte[] encrypted = ciphertext.toBytes();

		PlaintextContainer plain = ciphertext.decryptSymmetric(key);
		byte[] decrypted = plain.toBytes();

		assertEquals(new String(plaintext, StandardCharsets.UTF_8), plain.toString(StandardCharsets.UTF_8));

	}

	// - String encrypt + key, return: encrypted String
	@Test
	void testSymmetricStringEncryptionWithExistingKey()
			throws NoSuchAlgorithmException, CoseException, InvalidKeyException, SCCException {
		// SCCKey already exists
		SCCKey existingKey = SCCKey.createKey(KeyUseCase.SymmetricEncryption);
		byte[] existingSCCKey = existingKey.decodeObjectToBytes();
						

		String plaintext = "Hello World!";
		SCCKey key = SCCKey.createFromExistingKey(existingSCCKey);
		SCCCiphertext ciphertext = scc.encryptSymmetric(key, plaintext.getBytes(StandardCharsets.UTF_8));
		String encrypted = ciphertext.toBase64();

		PlaintextContainer plain = ciphertext.decryptSymmetric(key);
		String decrypted = plain.toString(StandardCharsets.UTF_8);

		assertEquals(plaintext, decrypted);
	}

	// - encrypted byte[] encrypt + key, return: encrypted byte[]
	@Test
	void testSymmetricByteReEncyptionWithKey()
			throws CoseException, NoSuchAlgorithmException, InvalidKeyException, SCCException {
		byte[] plaintext = "Hello World!".getBytes();
		SCCKey key = SCCKey.createKey(KeyUseCase.SymmetricEncryption);
		// Encryption
		SCCCiphertext ciphertext = scc.encryptSymmetric(key, plaintext);
		// ReEncryption
		SCCCiphertext updatedCiphertext = scc.reEncryptSymmetric(key, ciphertext);
		byte[] updateCiphertext = updatedCiphertext.toBytes();

		String oldCiphertext = ciphertext.toBase64();
		String newCiphertext = updatedCiphertext.toBase64();

		assertNotEquals(oldCiphertext, newCiphertext);
	}

	// - encrypted String encrypt + key, return: encrypted String
	@Test
	void testSymmetricStringReEncyptionWithKey()
			throws CoseException, NoSuchAlgorithmException, InvalidKeyException, SCCException {
		String plaintext = "Hello World!";

		SCCKey key = SCCKey.createKey(KeyUseCase.SymmetricEncryption);
		// Encryption
		SCCCiphertext ciphertext = scc.encryptSymmetric(key, plaintext.getBytes(StandardCharsets.UTF_8));
		// ReEncryption
		SCCCiphertext updatedCiphertext = scc.reEncryptSymmetric(key, ciphertext);
		String updateCiphertext = updatedCiphertext.toBase64();

		String oldCiphertext = ciphertext.toBase64();
		String newCiphertext = updatedCiphertext.toBase64();

		assertNotEquals(oldCiphertext, newCiphertext);
	}

	// - encrypted byte[] encrypt + password, return: encrypted byte[]
	@Test
	void testSymmetricByteReEncyptionWitPassword() throws CoseException, InvalidKeyException, SCCException {
		byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
		byte[] password = "password".getBytes(StandardCharsets.UTF_8);
		SCCKey key = SCCKey.createSymmetricKeyWithPassword(password);
		// Encryption
		SCCCiphertext ciphertext = scc.encryptSymmetric(key, plaintext);
		// ReEncryption
		SCCCiphertext updatedCiphertext = scc.reEncryptSymmetric(key, ciphertext);
		byte[] updateCiphertext = updatedCiphertext.toBytes();

		String oldCiphertext = ciphertext.toBase64();
		String newCiphertext = updatedCiphertext.toBase64();

		assertNotEquals(oldCiphertext, newCiphertext);
	}

	// - encrypted String encrypt + password, return: encrypted String
	@Test
	void testSymmetricStringReEncyptionWithPassword() throws CoseException, InvalidKeyException, SCCException {
		String plaintext = "Hello World!";
		String password = "password";
		SCCKey key = SCCKey.createSymmetricKeyWithPassword(password.getBytes(StandardCharsets.UTF_8));
		// Encryption
		SCCCiphertext ciphertext = scc.encryptSymmetric(key, plaintext.getBytes(StandardCharsets.UTF_8));
		// ReEncryption
		SCCCiphertext updatedCiphertext = scc.reEncryptSymmetric(key, ciphertext);
		String updateCiphertext = updatedCiphertext.toBase64();

		String oldCiphertext = ciphertext.toBase64();
		String newCiphertext = updatedCiphertext.toBase64();

		assertNotEquals(oldCiphertext, newCiphertext);
	}

}
