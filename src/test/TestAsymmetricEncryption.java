package test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import org.junit.jupiter.api.Test;
import org.securecryptoconfig.PlaintextContainer;
import org.securecryptoconfig.SCCCiphertext;
import org.securecryptoconfig.SCCException;
import org.securecryptoconfig.SCCKey;
import org.securecryptoconfig.SCCKeyPair;
import org.securecryptoconfig.SecureCryptoConfig;
import org.securecryptoconfig.SCCKey.KeyType;
import org.securecryptoconfig.SCCKey.KeyUseCase;

import COSE.CoseException;

class TestAsymmetricEncryption {

	SecureCryptoConfig scc = new SecureCryptoConfig();

	// Use Cases:
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
	 * @throws SCCException 
	 */

	// - byte[] encrypt, return: encrypted byte[] + new key
	// - encrypted byte[] decrypt + key, return: decrypted byte[]
	@Test
	void testAymmetricByteDecryptWithKey() throws CoseException, NoSuchAlgorithmException, InvalidKeyException, SCCException {
		byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
		SCCKey pair = SCCKey.createKey(KeyUseCase.AsymmetricEncryption);
		// Encryption
		SCCCiphertext ciphertext = scc.encryptAsymmetric(pair, plaintext);
		// Decryption
		PlaintextContainer plain = ciphertext.decryptAsymmetric(pair);
		byte[] decrypted = plain.toBytes();

		assertEquals(new String(plaintext, StandardCharsets.UTF_8), plain.toString(StandardCharsets.UTF_8));
	}

	// - String encrypt, return: encrypted String + new key
	// - encrypted String decrypt + key, return: decrypted String
	@Test
	void testAsymmetricStringDecryptWithKey() throws CoseException, NoSuchAlgorithmException, InvalidKeyException, SCCException {
		String plaintext = "Hello World!";
		SCCKey pair = SCCKey.createKey(KeyUseCase.AsymmetricEncryption);
		// Encryption
		SCCCiphertext ciphertext = scc.encryptAsymmetric(pair, plaintext.getBytes(StandardCharsets.UTF_8));
		// Decryption
		PlaintextContainer decryptedCiphertext = ciphertext.decryptAsymmetric(pair);
		String decrypted = decryptedCiphertext.toString(StandardCharsets.UTF_8);

		assertEquals(plaintext, decrypted);

	}

	// - byte[] encrypt + key, return: encrypted byte[]
	@Test
	void testAsymmetricByteEncryptionWithExistingKey() throws NoSuchAlgorithmException, CoseException, InvalidKeyException, SCCException {
		// KeyPair already exists
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(4096);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();

		// Convert existing pair to SCCKeyPair
		SCCKey pair = new SCCKey(KeyType.Asymmetric, keyPair.getPublic().getEncoded(), keyPair.getPrivate().getEncoded(), "RSA");
				
		byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
		SCCCiphertext ciphertext = scc.encryptAsymmetric(pair, plaintext);
		byte[] encrypted = ciphertext.toBytes();

		PlaintextContainer plain = ciphertext.decryptAsymmetric(pair);
		byte[] decrypted = plain.toBytes();

		assertEquals(new String(plaintext, StandardCharsets.UTF_8), plain.toString(StandardCharsets.UTF_8));

	}

	// - String encrypt + key, return: encrypted String
	@Test
	void testAsymmetricStringEncryptionWithExistingKey() throws NoSuchAlgorithmException, CoseException, InvalidKeyException, SCCException {
		// KeyPair already exists
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(4096);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();

		// Convert existing pair to SCCKeyPair
		SCCKey pair = new SCCKey(KeyType.Asymmetric, keyPair.getPublic().getEncoded(), keyPair.getPrivate().getEncoded(), "RSA");
		
		String plaintext = "Hello World!";
		SCCCiphertext ciphertext = scc.encryptAsymmetric(pair, plaintext.getBytes(StandardCharsets.UTF_8));
		String encrypted = ciphertext.toString(StandardCharsets.UTF_8);

		PlaintextContainer decryptedCiphertext = ciphertext.decryptAsymmetric(pair);
		String decrypted = decryptedCiphertext.toString(StandardCharsets.UTF_8);

		assertEquals(plaintext, decrypted);
	}

	// - encrypted byte[] encrypt + key, return: encrypted byte[]
	@Test
	void testAsymmetricByteReEncyptionWithKey() throws CoseException, NoSuchAlgorithmException, InvalidKeyException, SCCException {
		byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
		SCCKey pair = SCCKey.createKey(KeyUseCase.AsymmetricEncryption);
		// Encryption
		SCCCiphertext ciphertext = scc.encryptAsymmetric(pair, plaintext);
		// ReEncryption
		SCCCiphertext updatedCiphertext = scc.reEncryptAsymmetric(pair, ciphertext);
		byte[] updateCiphertect = updatedCiphertext.toBytes();
		// byte[] updateCiphertext = updatedCiphertext.getCiphertextBytes();

		String oldCiphertext = ciphertext.toString(StandardCharsets.UTF_8);
		String newCiphertext = updatedCiphertext.toString(StandardCharsets.UTF_8);

		assertFalse(oldCiphertext.equals(newCiphertext));
	}

	// - encrypted String encrypt + key, return: encrypted String
	@Test
	void testAsymmetricStringReEncyptionWithKey() throws CoseException, NoSuchAlgorithmException, InvalidKeyException, SCCException {
		String plaintext = "Hello World!";
		SCCKey pair = SCCKey.createKey(KeyUseCase.AsymmetricEncryption);
		// Encryption
		SCCCiphertext ciphertext = scc.encryptAsymmetric(pair, plaintext.getBytes(StandardCharsets.UTF_8));
		// ReEncryption
		SCCCiphertext updatedCiphertext = scc.reEncryptAsymmetric(pair, ciphertext);
		String updateCiphertext = updatedCiphertext.toString(StandardCharsets.UTF_8);

		String oldCiphertext = ciphertext.toString(StandardCharsets.UTF_8);
		String newCiphertext = updatedCiphertext.toString(StandardCharsets.UTF_8);

		assertFalse(oldCiphertext.equals(newCiphertext));
	}

}
