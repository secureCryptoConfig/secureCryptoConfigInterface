package test;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.junit.jupiter.api.Test;

import COSE.AlgorithmID;
import COSE.Attribute;
import COSE.CoseException;
import COSE.Encrypt0Message;
import COSE.HeaderKeys;
import main.PlaintextContainer;
import main.SCCCiphertext;
import main.SCCCiphertextOutputStream;
import main.SCCHash;
import main.SCCKey;
import main.SCCKey.SCCKeyAlgorithm;
import main.SCCKeyPair;
import main.SCCKeyPair.keyPairUseCase;
import main.SCCPasswordHash;
import main.SCCSignature;
import main.SecureCryptoConfig;
import main.UseCases;

class SecureCryptoConfigTest {

	SecureCryptoConfig scc = new SecureCryptoConfig();
	String inputPlaintext = "very confidential";
	PlaintextContainer plaintextContainer = new PlaintextContainer(inputPlaintext.getBytes());
	String filepath = ".\\src\\main\\Test.txt";

	// Use Cases:
	// TODO RFC use cases
	// encryption:
	// - byte[] encrypt, return: encrypted byte[] + new key
	// - byte[] encrypt + password, return: encrypted byte[] + new key
	// - String encrypt, return: encrypted String + new key
	// - String encrypt + password, return: encrypted String + new key

	// - byte[] encrypt + key, return: encrypted byte[]
	// - String encrypt + key, return: encrypted String

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

	
	

	// - byte[] encrypt, return: encrypted byte[] + new key
	@Test
	void testSymmetricByteEncryptNoExistingKey() throws CoseException {
		byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
		SCCKey key = SCCKey.createSymmetricKey();
		SCCCiphertext cipher = scc.symmetricEncrypt(key, new PlaintextContainer(plaintext));
		byte[] encrypted = cipher.getCipherBytes();
	}

	// - byte[] encrypt + password, return: encrypted byte[] + new key
	@Test
	void testSymmetricByteEncryptWithPassword() throws CoseException {
		byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
		byte[] password = "Password!".getBytes(StandardCharsets.UTF_8);
		SCCKey key = SCCKey.createKey(new PlaintextContainer(password));
		SCCCiphertext cipher = scc.symmetricEncrypt(key, new PlaintextContainer(plaintext));
		byte[] encrypted = cipher.getCipherBytes();
	}

	// - String encrypt, return: encrypted String + new key
	@Test
	void testSymmetricStringEncryptNoExistingKey() throws CoseException {
		String plaintext = "Hello World!";
		SCCKey key = SCCKey.createSymmetricKey();
		SCCCiphertext cipher = scc.symmetricEncrypt(key,
				new PlaintextContainer(plaintext.getBytes(StandardCharsets.UTF_8)));
		String encrypted = cipher.getPlain().getString(StandardCharsets.UTF_8);
	}

	// - String encrypt + password, return: encrypted String + new key
	void testSymmetricStringEncryptWithPassword() throws CoseException {
		String plaintext = "Hello World!";
		String password = "password";
		SCCKey key = SCCKey.createKey(new PlaintextContainer(password.getBytes(StandardCharsets.UTF_8)));
		SCCCiphertext cipher = scc.symmetricEncrypt(key,
				new PlaintextContainer(plaintext.getBytes(StandardCharsets.UTF_8)));
		String encrypted = cipher.getPlain().getString(StandardCharsets.UTF_8);
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
		SCCCiphertext cipher = scc.symmetricEncrypt(key, new PlaintextContainer(plaintext));
		byte[] encrypted = cipher.getCipherBytes();

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
		SCCCiphertext cipher = scc.symmetricEncrypt(key,
				new PlaintextContainer(plaintext.getBytes(StandardCharsets.UTF_8)));
		String encrypted = cipher.getPlain().getString(StandardCharsets.UTF_8);
	}

	// - encrypted byte[] decrypt + key, return: decrypted byte[]
	@Test
	void testSymmetricByteDecryptWithKey() throws CoseException {
		byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
		SCCKey key = SCCKey.createSymmetricKey();
		// Encryption
		SCCCiphertext cipher = scc.symmetricEncrypt(key, plaintextContainer);
		// Decryption
		PlaintextContainer plain = cipher.symmetricDecrypt(key);
		byte[] decrypted = plain.getByteArray();
	}
	

	// - encrypted String decrypt + key, return: decrypted String
	@Test
	void testSymmetricStringDecryptWithKey() throws CoseException {
		String plaintext = "Hello World!";
		SCCKey key = SCCKey.createSymmetricKey();
		// Encryption
		SCCCiphertext cipher = scc.symmetricEncrypt(key, new PlaintextContainer(plaintext.getBytes(StandardCharsets.UTF_8)));
		// Decryption
		PlaintextContainer plain = cipher.symmetricDecrypt(key);
		String decrypted = plain.getString(StandardCharsets.UTF_8);
	}


	// - encrypted byte[] decrypt + password, return: decrypted byte[]
	@Test
	void testSymmetricByteDecryptWithPassword() throws CoseException {
		byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
		PlaintextContainer plaintextContainer = new PlaintextContainer(plaintext);
		byte[] password = "Password!".getBytes(StandardCharsets.UTF_8);
		SCCKey key = SCCKey.createKey(new PlaintextContainer(password));
		// Encryption
		SCCCiphertext cipher = scc.symmetricEncrypt(key, plaintextContainer);
		// Decryption
		PlaintextContainer plain = cipher.symmetricDecrypt(key);
		byte[] decrypted = plain.getByteArray();
	}
	
	// - encrypted String decrypt + password, return: decrypted String
	@Test
	void testSymmetricStringDecryptWithPassword() throws CoseException {
		String plaintext = "Hello World!";
		String password = "password";
		SCCKey key = SCCKey.createKey(new PlaintextContainer(password.getBytes(StandardCharsets.UTF_8)));
		// Encryption
		SCCCiphertext cipher = scc.symmetricEncrypt(key, new PlaintextContainer(plaintext.getBytes(StandardCharsets.UTF_8)));
		// Decryption
		PlaintextContainer plain = cipher.symmetricDecrypt(key);
		String decrypted = plain.getString(StandardCharsets.UTF_8);
	}
	
	// - encrypted byte[] encrypt + key, return: encrypted byte[]
	@Test
	void testSymmetricByteReEncyptionWithKey() throws CoseException {
		byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
		SCCKey key = SCCKey.createSymmetricKey();
		// Encryption
		SCCCiphertext cipher = scc.symmetricEncrypt(key, new PlaintextContainer(plaintext));
		// ReEncryption
		SCCCiphertext updatedCipher = scc.symmetricReEncrypt(key, cipher);
		byte[] decrypted = updatedCipher.getCipherBytes();
	}
	
	// - encrypted String encrypt + key, return: encrypted String
	@Test
	void testSymmetricStringReEncyptionWithKey() throws CoseException {
		String plaintext = "Hello World!";
		SCCKey key = SCCKey.createSymmetricKey();
		// Encryption
		SCCCiphertext cipher = scc.symmetricEncrypt(key, new PlaintextContainer(plaintext.getBytes(StandardCharsets.UTF_8)));
		// ReEncryption
		SCCCiphertext updatedCipher = scc.symmetricReEncrypt(key, cipher);
		String decrypted = updatedCipher.getPlain().getString(StandardCharsets.UTF_8);
	}
	
	// - encrypted byte[] encrypt + password, return: encrypted byte[]
	@Test
	void testSymmetricByteReEncyptionWitPassword() throws CoseException {
		byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
		byte[] password = "password".getBytes(StandardCharsets.UTF_8);
		SCCKey key = SCCKey.createKey(new PlaintextContainer(password));
		// Encryption
		SCCCiphertext cipher = scc.symmetricEncrypt(key, plaintextContainer);
		// ReEncryption
		SCCCiphertext updatedCipher = scc.symmetricReEncrypt(key, cipher);
		byte[] decrypted = updatedCipher.getCipherBytes();
	}
	
	// - encrypted String encrypt + password, return: encrypted String
	void testSymmetricStringReEncyptionWithPassword() throws CoseException {
		String plaintext = "Hello World!";
		String password = "password";
		SCCKey key = SCCKey.createKey(new PlaintextContainer(password.getBytes(StandardCharsets.UTF_8)));
		// Encryption
		SCCCiphertext cipher = scc.symmetricEncrypt(key, new PlaintextContainer(plaintext.getBytes(StandardCharsets.UTF_8)));
		// ReEncryption
		SCCCiphertext updatedCipher = scc.symmetricReEncrypt(key, cipher);
		String decrypted = updatedCipher.getPlain().getString(StandardCharsets.UTF_8);
	}
	
	// Use Cases:
	// TODO RFC use cases
	// Hash:


	// Test for Hashing -> hash two times same plain
	// @Test
	void testHashing() throws CoseException {

		SCCHash hashed = scc.hash(plaintextContainer);

		String hash = hashed.getHashedContent().getBase64();

		SCCHash hashed1 = scc.hash(plaintextContainer);
		String hash2 = hashed1.getHashedContent().getBase64();

		assertEquals(hash, hash2);

	}

	// @Test
	void testSCCasymmetricEncryption() throws CoseException, NoSuchAlgorithmException {

		SCCKeyPair pair = SCCKeyPair.createKeyPair(keyPairUseCase.AsymmetricEncryption);

		SCCCiphertext encrypted = scc.asymmetricEncrypt(pair, plaintextContainer);
		PlaintextContainer decrypted = scc.asymmetricDecrypt(pair, encrypted);
		// PlaintextContainer decrypted = encrypted.asymmetricDecrypt(pair);

		assertEquals(inputPlaintext, decrypted.getString(StandardCharsets.UTF_8));

	}

	// @Test
	void testSCCSignature() throws CoseException, NoSuchAlgorithmException, InvalidKeySpecException {
		SCCKeyPair k = SCCKeyPair.createKeyPair(keyPairUseCase.Signing);

		SCCSignature s = scc.sign(k, plaintextContainer);
		// Sign1Message msg = s.convertByteToMsg();
		// String signature = s.getSignature().getString();

		boolean result = scc.validateSignature(k, s);
		// boolean result = s.validateSignature(k);

		assertEquals(true, result);
	}

	// @Test
	void testPasswordHash() throws CoseException {

		SCCPasswordHash hashed = scc.passwordHash(plaintextContainer);

		// String hash = hashed.getHashedContent().getString();

		boolean result = scc.validatePasswordHash(plaintextContainer, hashed);
		// boolean result = hashed.verifyHash(plaintextContainer);

		assertEquals(result, true);

	}

	// @Test
	void testFileEncryption() throws NoSuchAlgorithmException, CoseException {
		// retrieve content of file for encryption for later comparison
		String fileInput = UseCases.readFile(filepath).replace("\r", "").replace("\n", "");

		SCCKey scckey = SCCKey.createSymmetricKey();
		SCCCiphertext c = scc.fileEncrypt(scckey, filepath);
		PlaintextContainer p = scc.fileDecrypt(scckey, c, filepath);
		String decrypted = p.getString(StandardCharsets.UTF_8).replace("\r", "").replace("\n", "");
		assertEquals(true, decrypted.equals(fileInput));
	}

	// @Test
	void testFileStream() throws NoSuchAlgorithmException, CoseException {
		File file = new File(filepath);
		SCCKey scckey = SCCKey.createSymmetricKey();

		try {
			FileInputStream inputStream = new FileInputStream(file);
			SCCCiphertextOutputStream s = scc.streamEncrypt(scckey, inputStream);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

}
