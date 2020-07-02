package test;

import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import org.junit.jupiter.api.Test;

import COSE.CoseException;
import main.PlaintextContainer;
import main.SCCCiphertext;
import main.SCCKey;
import main.SCCKey.SCCKeyAlgorithm;
import main.SecureCryptoConfig;

class TestSymmetricEncryption {

	SecureCryptoConfig scc = new SecureCryptoConfig();
	String filepath = null;

	// Use Cases:
	// TODO RFC use cases
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
	 */
	

	// - byte[] encrypt, return: encrypted byte[] + new key
	@Test
	void testSymmetricByteEncryptNoExistingKey() throws CoseException {
		byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
		SCCKey key = SCCKey.createSymmetricKey();
		SCCCiphertext ciphertext = scc.encryptSymmetric(key, plaintext);
		byte[] encrypted = ciphertext.toBytes();
		
		assertTrue(encrypted instanceof byte[]);
		assertTrue(key instanceof SCCKey);
		
	}

	// - byte[] encrypt + password, return: encrypted byte[] + new key
	@Test
	void testSymmetricByteEncryptWithPassword() throws CoseException {
		byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
		byte[] password = "Password!".getBytes(StandardCharsets.UTF_8);
		SCCKey key = SCCKey.createKeyWithPassword(password);
		SCCCiphertext ciphertext = scc.encryptSymmetric(key, plaintext);
		byte[] encrypted = ciphertext.toBytes();
		
		assertTrue(encrypted instanceof byte[]);
		assertTrue(key instanceof SCCKey);
	}

	// - String encrypt, return: encrypted String + new key
	@Test
	void testSymmetricStringEncryptNoExistingKey() throws CoseException {
		String plaintext = "Hello World!";
		SCCKey key = SCCKey.createSymmetricKey();
		SCCCiphertext ciphertext = scc.encryptSymmetric(key, plaintext.getBytes(StandardCharsets.UTF_8));
		String encrypted = ciphertext.toString(StandardCharsets.UTF_8);
		
		assertTrue(encrypted instanceof String);
		assertTrue(key instanceof SCCKey);
	}

	// - String encrypt + password, return: encrypted String + new key
	void testSymmetricStringEncryptWithPassword() throws CoseException {
		String plaintext = "Hello World!";
		String password = "password";
		SCCKey key = SCCKey.createKeyWithPassword(password.getBytes(StandardCharsets.UTF_8));
		SCCCiphertext ciphertext = scc.encryptSymmetric(key, plaintext.getBytes(StandardCharsets.UTF_8));
		String encrypted = ciphertext.toString(StandardCharsets.UTF_8);
		
		assertTrue(encrypted instanceof String);
		assertTrue(key instanceof SCCKey);
	}

	// - byte[] encrypt + key, return: encrypted byte[]
	@Test
	void testSymmetricByteEncryptionWithExistingKey() throws NoSuchAlgorithmException, CoseException {
		// Some bytes for a key
		byte[] existingKeyBytes = new byte[32];
		SecureRandom random = SecureRandom.getInstanceStrong();
		random.nextBytes(existingKeyBytes);

		byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
		SCCKey key = new SCCKey(existingKeyBytes, SCCKeyAlgorithm.AES);
		SCCCiphertext ciphertext = scc.encryptSymmetric(key, plaintext);
		byte[] encrypted = ciphertext.toBytes();
		
		assertTrue(encrypted instanceof byte[]);
	}

	// - String encrypt + key, return: encrypted String
	@Test
	void testSymmetricStringEncryptionWithExistingKey() throws NoSuchAlgorithmException, CoseException {
		// Some bytes for a key
		byte[] existingKeyBytes = new byte[32];
		SecureRandom random = SecureRandom.getInstanceStrong();
		random.nextBytes(existingKeyBytes);

		String plaintext = "Hello World!";
		SCCKey key = new SCCKey(existingKeyBytes, SCCKeyAlgorithm.AES);
		SCCCiphertext ciphertext = scc.encryptSymmetric(key, plaintext.getBytes(StandardCharsets.UTF_8));
		String encrypted = ciphertext.toString(StandardCharsets.UTF_8);
		
		assertTrue(encrypted instanceof String);
	}

	// - encrypted byte[] decrypt + key, return: decrypted byte[]
	@Test
	void testSymmetricByteDecryptWithKey() throws CoseException {
		byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
		SCCKey key = SCCKey.createSymmetricKey();
		// Encryption
		SCCCiphertext ciphertext = scc.encryptSymmetric(key,plaintext);
		// Decryption
		PlaintextContainer plain = ciphertext.decryptSymmetric(key);
		byte[] decrypted = plain.toBytes();
		
		assertEquals(new String(plaintext, StandardCharsets.UTF_8), plain.toString(StandardCharsets.UTF_8));
	}
	

	// - encrypted String decrypt + key, return: decrypted String
	@Test
	void testSymmetricStringDecryptWithKey() throws CoseException {
		String plaintext = "Hello World!";
		SCCKey key = SCCKey.createSymmetricKey();
		// Encryption
		SCCCiphertext ciphertext = scc.encryptSymmetric(key, plaintext.getBytes(StandardCharsets.UTF_8));
		// Decryption
		PlaintextContainer plain = ciphertext.decryptSymmetric(key);
		String decrypted = plain.toString(StandardCharsets.UTF_8);
		
		assertEquals(plaintext, decrypted);
		
	}


	// - encrypted byte[] decrypt + password, return: decrypted byte[]
	@Test
	void testSymmetricByteDecryptWithPassword() throws CoseException {
		byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
		byte[] password = "Password!".getBytes(StandardCharsets.UTF_8);
		SCCKey key = SCCKey.createKeyWithPassword(password);
		// Encryption
		SCCCiphertext ciphertext = scc.encryptSymmetric(key, plaintext);
		// Decryption
		PlaintextContainer plain = ciphertext.decryptSymmetric(key);
		byte[] decrypted = plain.toBytes();
		
		assertEquals(new String(plaintext, StandardCharsets.UTF_8), plain.toString(StandardCharsets.UTF_8));
		
	}
	
	// - encrypted String decrypt + password, return: decrypted String
	@Test
	void testSymmetricStringDecryptWithPassword() throws CoseException {
		String plaintext = "Hello World!";
		String password = "password";
		SCCKey key = SCCKey.createKeyWithPassword(password.getBytes(StandardCharsets.UTF_8));
		// Encryption
		SCCCiphertext ciphertext = scc.encryptSymmetric(key, plaintext.getBytes(StandardCharsets.UTF_8));
		
		// Decryption
		PlaintextContainer plain = ciphertext.decryptSymmetric(key);
		String decrypted = plain.toString(StandardCharsets.UTF_8);
		
		assertEquals(plaintext, decrypted);
		
	}
	
	// - encrypted byte[] encrypt + key, return: encrypted byte[]
	@Test
	void testSymmetricByteReEncyptionWithKey() throws CoseException {
		byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
		SCCKey key = SCCKey.createSymmetricKey();
		// Encryption
		SCCCiphertext ciphertext = scc.encryptSymmetric(key,plaintext);
		// ReEncryption
		SCCCiphertext updatedCiphertext = scc.reEncryptSymmetric(key, ciphertext);
		byte[] updateCiphertext = updatedCiphertext.toBytes();
		
		String oldCiphertext = ciphertext.toString(StandardCharsets.UTF_8);
		String newCiphertext = updatedCiphertext.toString(StandardCharsets.UTF_8);
		
		assertFalse(oldCiphertext.equals(newCiphertext));
	}
	
	// - encrypted String encrypt + key, return: encrypted String
	@Test
	void testSymmetricStringReEncyptionWithKey() throws CoseException {
		String plaintext = "Hello World!";
		SCCKey key = SCCKey.createSymmetricKey();
		// Encryption
		SCCCiphertext ciphertext = scc.encryptSymmetric(key, plaintext.getBytes(StandardCharsets.UTF_8));
		// ReEncryption
		SCCCiphertext updatedCiphertext = scc.reEncryptSymmetric(key, ciphertext);
		String updateCiphertext = updatedCiphertext.toString(StandardCharsets.UTF_8);
		
		String oldCiphertext = ciphertext.toString(StandardCharsets.UTF_8);
		String newCiphertext = updatedCiphertext.toString(StandardCharsets.UTF_8);
		
		assertFalse(oldCiphertext.equals(newCiphertext));
	}
	
	// - encrypted byte[] encrypt + password, return: encrypted byte[]
	@Test
	void testSymmetricByteReEncyptionWitPassword() throws CoseException {
		byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
		byte[] password = "password".getBytes(StandardCharsets.UTF_8);
		SCCKey key = SCCKey.createKeyWithPassword(password);
		// Encryption
		SCCCiphertext ciphertext = scc.encryptSymmetric(key, plaintext);
		// ReEncryption
		SCCCiphertext updatedCiphertext = scc.reEncryptSymmetric(key, ciphertext);
		byte[] updateCiphertext = updatedCiphertext.toBytes();
		
		String oldCiphertext = ciphertext.toString(StandardCharsets.UTF_8);
		String newCiphertext = updatedCiphertext.toString(StandardCharsets.UTF_8);
		
		assertFalse(oldCiphertext.equals(newCiphertext));
	}
	
	// - encrypted String encrypt + password, return: encrypted String
	@Test
	void testSymmetricStringReEncyptionWithPassword() throws CoseException {
		String plaintext = "Hello World!";
		String password = "password";
		SCCKey key = SCCKey.createKeyWithPassword(password.getBytes(StandardCharsets.UTF_8));
		// Encryption
		SCCCiphertext ciphertext = scc.encryptSymmetric(key, plaintext.getBytes(StandardCharsets.UTF_8));
		// ReEncryption
		SCCCiphertext updatedCiphertext = scc.reEncryptSymmetric(key, ciphertext);
		String updateCiphertext = updatedCiphertext.toString(StandardCharsets.UTF_8);
		
		String oldCiphertext = ciphertext.toString(StandardCharsets.UTF_8);
		String newCiphertext = updatedCiphertext.toString(StandardCharsets.UTF_8);
		
		assertFalse(oldCiphertext.equals(newCiphertext));
	}
	
}
