package test;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import org.junit.jupiter.api.Test;

import COSE.CoseException;
import main.PlaintextContainer;
import main.SCCCiphertext;
import main.SCCCiphertextOutputStream;
import main.SCCHash;
import main.SCCKey;
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
	// - String encrypt, return: encrypted String + new key
	// - File/Stream encrypt, return: encrypting Outputstream + new key
	// - byte[] encrypt + key, return: encrypted byte[]
	// - String encrypt + key, return: encrypted String
	// - File/Stream encrypt + key, return: encrypting Outputstream
	// - byte[] encrypt + password, return: encrypted byte[]
	// - String encrypt + password, return: encrypted String
	// - File/Stream encrypt + password, return: encrypting Outputstream

	// ReEncrypt
	// - encrypted byte[] encrypt + key, return: encrypted byte[]
	// - encrypted String encrypt + key, return: encrypted String
	// - encrypted File/Stream encrypt + key, return: encrypting Outputstream
	// - encrypted byte[] encrypt + password, return: encrypted byte[]
	// - encrypted String encrypt + password, return: encrypted String
	// - encrypted File/Stream encrypt + password, return: encrypting Outputstream

	// decryption:
	// - encrypted byte[] decrypt + key, return: decrypted byte[]
	// - encrypted String decrypt + key, return: decrypted String
	// - encrypted File/Stream decrypt + key, return: decrypting Inputstream
	// - encrypted byte[] decrypt + password, return: decrypted byte[]
	// - encrypted String decrypt + password, return: decrypted String
	// - encrypted File/Stream decrypt + password, return: decrypting Inputstream

	// - byte[] encrypt, return: encrypted byte[] + new key
	/**
	 * @Test void testSymmetricByteEncryptNoExistingKey() throws CoseException {
	 *       byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
	 *       //byte[] cipherText = plaintext.encrypt(); }
	 * 
	 * @Test void testSymmetricByteEncryptWithPassword() throws CoseException {
	 *       byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
	 *       byte[] password = "Password!".getBytes(StandardCharsets.UTF_8);
	 *       //byte[] cipherText = plaintext.encrypt(password); }
	 * 
	 * @Test void testSymmetricByteDecryptWithPassword() throws CoseException {
	 * 
	 *       byte[] password = "Password!".getBytes(StandardCharsets.UTF_8);
	 *       //byte[] cipherText = plaintext.encrypt(password); byte[] plaintext =
	 *       cipherText.decrypt(password); }
	 **/

	//@Test
	void testSCCsymmetricEncryption() throws CoseException {

		// Key creation with Password
		PlaintextContainer password = new PlaintextContainer("Hello World".getBytes());
		SCCKey scckey = SCCKey.createKey(password);

		// Key creation without a password
		// SCCKey scckey = SCCKey.createKey();

		SCCCiphertext sccciphertext = scc.symmetricEncrypt(scckey, plaintextContainer);
		PlaintextContainer plain = scc.symmetricDecrypt(scckey, sccciphertext);
		// PlaintextContainer plain = sccciphertext.symmetricDecrypt(scckey);

		assertEquals(inputPlaintext, plain.getString(StandardCharsets.UTF_8));

	}

	// Test for Hashing -> hash two times same plain
	//@Test
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
	void testSCCSignature() throws CoseException, NoSuchAlgorithmException {
		SCCKeyPair k = SCCKeyPair.createKeyPair(keyPairUseCase.Signing);
		SCCSignature s = scc.sign(k, plaintextContainer);
		// Sign1Message msg = s.convertByteToMsg();
		// String signature = s.getSignature().getString();

		boolean result = scc.validateSignature(k, s);
		// boolean result = s.validateSignature(k);

		assertEquals(true, result);
	}

	//@Test
	void testPasswordHash() throws CoseException {

		SCCPasswordHash hashed = scc.passwordHash(plaintextContainer);

		// String hash = hashed.getHashedContent().getString();

		boolean result = scc.validatePasswordHash(plaintextContainer, hashed);
		// boolean result = hashed.verifyHash(plaintextContainer);

		assertEquals(result, true);

	}

	//@Test
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
