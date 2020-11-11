package org.securecryptoconfig;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import org.apache.commons.lang.ObjectUtils.Null;
import org.junit.jupiter.api.Test;
import org.securecryptoconfig.SCCKey.KeyType;
import org.securecryptoconfig.SCCKey.KeyUseCase;
import org.securecryptoconfig.SecureCryptoConfig.SCCAlgorithm;

import COSE.CoseException;

class TestSymmetricEncryption {

	/**
	 * Class for testing all functionalities for symmetric encryption from the
	 * Secure Crypto Config Interface
	 * 
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

		// Same with other String conversion
		String oldCiphertextString = ciphertext.toString();
		String newCiphertextString = updatedCiphertext.toString();

		assertNotEquals(oldCiphertextString, newCiphertextString);

		// Same with short-cut methods
		SCCCiphertext updatedCiphertext2 = ciphertext.reEncryptSymmetric(key);
		byte[] updateCiphertext2 = updatedCiphertext.toBytes();

		String newCiphertext2 = updatedCiphertext2.toBase64();

		assertNotEquals(oldCiphertext, newCiphertext2);
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

	// Tests for SCC files handling
	@Test
	void testSCCFileHandling() {
		// Set security level and get the policy name of the SCC file currently used
		SecureCryptoConfig.setSecurityLevel(5);
		String policyName = SecureCryptoConfig.getUsedSCC();
		assertEquals("SCC_SecurityLevel_5", policyName);

		// Set not existing security level
		assertThrows(IllegalArgumentException.class, () -> SecureCryptoConfig.setSecurityLevel(7));

		// Go back to default SCC
		SecureCryptoConfig.setDefaultSCC();
		String policyName1 = SecureCryptoConfig.getUsedSCC();
		assertEquals("SCC_SecurityLevel_5", policyName1);

		// Set specific SCC file with desired policyName
		SecureCryptoConfig.setSCCFile("SCC_SecurityLevel_5");
		String policyName2 = SecureCryptoConfig.getUsedSCC();
		assertEquals("SCC_SecurityLevel_5", policyName2);

		// Set specific SCC file with not existing policyName
		assertThrows(InvalidParameterException.class, () -> SecureCryptoConfig.setSCCFile("WrongName"));

		// Set custom path that is not existing
		Path p = Paths.get("NoExistingPath");
		assertThrows(InvalidPathException.class, () -> SecureCryptoConfig.setCustomSCCPath(p));

	}

	@Test
	void testWrongKeyType() throws SCCException {
		String plaintext = "Hello World!";

		SCCKey keyAsym = SCCKey.createKey(KeyUseCase.AsymmetricEncryption);
		assertThrows(SCCException.class,
				() -> scc.encryptSymmetric(keyAsym, plaintext.getBytes(StandardCharsets.UTF_8)));

		SCCKey keySym = SCCKey.createKey(KeyUseCase.SymmetricEncryption);
		assertThrows(SCCException.class,
				() -> scc.encryptAsymmetric(keySym, plaintext.getBytes(StandardCharsets.UTF_8)));

		assertThrows(SCCException.class, () -> scc.sign(keySym, plaintext.getBytes(StandardCharsets.UTF_8)));

	}

	@Test
	void testSymmetricEncryptionWithSpecificAlgo() throws SCCException {
		// Set specific algorithm
		SecureCryptoConfig.setAlgorithm(SCCAlgorithm.AES_GCM_192_96);

		byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
		byte[] password = "password".getBytes(StandardCharsets.UTF_8);
		SCCKey key = SCCKey.createSymmetricKeyWithPassword(password);

		// Encryption
		SCCCiphertext ciphertext = scc.encryptSymmetric(key, plaintext);

		assertNotEquals(Base64.getEncoder().encodeToString(plaintext), ciphertext.toBase64());
		assertNotEquals(0, ciphertext.toBytes().length);

		// Decryption
		PlaintextContainer plain = scc.decryptSymmetric(key, ciphertext);
		byte[] decrypted = plain.toBytes();

		assertEquals(new String(plaintext, StandardCharsets.UTF_8), plain.toString(StandardCharsets.UTF_8));

		SecureCryptoConfig.defaultAlgorithm();
	}

	@Test
	void testSymmetricEncryptionWithSpecificAlgo2() throws SCCException {
		// Set specific algorithm
		SecureCryptoConfig.setAlgorithm(SCCAlgorithm.AES_GCM_128_96);

		byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
		byte[] password = "password".getBytes(StandardCharsets.UTF_8);
		SCCKey key = SCCKey.createSymmetricKeyWithPassword(password);

		// Encryption
		SCCCiphertext ciphertext = scc.encryptSymmetric(key, plaintext);

		assertNotEquals(Base64.getEncoder().encodeToString(plaintext), ciphertext.toBase64());
		assertNotEquals(0, ciphertext.toBytes().length);

		// Decryption
		PlaintextContainer plain = scc.decryptSymmetric(key, ciphertext);
		byte[] decrypted = plain.toBytes();

		assertEquals(new String(plaintext, StandardCharsets.UTF_8), plain.toString(StandardCharsets.UTF_8));

		SecureCryptoConfig.defaultAlgorithm();
	}

	@Test
	void testSymmetricEncryptionWithWrongAlgo() throws SCCException {

		String plaintext = "Hello World!";
		SCCKey key = SCCKey.createKey(KeyUseCase.SymmetricEncryption);

		// Set specific algorithm
		SecureCryptoConfig.setAlgorithm(SCCAlgorithm.ECDSA_256);
		// Encryption
		assertThrows(SCCException.class, () -> scc.encryptSymmetric(key, plaintext.getBytes(StandardCharsets.UTF_8)));

		SecureCryptoConfig.defaultAlgorithm();
	}

	// Test SCCKey
	@Test
	void testSCCKeyWrongAlgo() throws SCCException {
		// Set specific wrong algorithm
		SecureCryptoConfig.setAlgorithm(SCCAlgorithm.ECDSA_256);
		assertThrows(NullPointerException.class, () -> SCCKey.createKey(KeyUseCase.SymmetricEncryption));
		
		byte[] passwordBytes = "Password".getBytes();
		assertThrows(SCCException.class, () -> SCCKey.createSymmetricKeyWithPassword(passwordBytes));
		assertThrows(SCCException.class, () -> SCCKey.createSymmetricKeyWithPassword(new PlaintextContainer(passwordBytes)));

		SecureCryptoConfig.setAlgorithm(SCCAlgorithm.AES_GCM_128_96);
		assertThrows(SCCException.class, () -> SCCKey.createKey(KeyUseCase.AsymmetricEncryption));
		assertThrows(SCCException.class, () -> SCCKey.createKey(KeyUseCase.Signing));

		SecureCryptoConfig.defaultAlgorithm();

	}

	@Test
	void testSCCKey() throws SCCException {

		// Set specific algorithm
		SecureCryptoConfig.setAlgorithm(SCCAlgorithm.AES_GCM_192_96);
		SCCKey key = SCCKey.createKey(KeyUseCase.SymmetricEncryption);

		assertThrows(SCCException.class, () -> key.getPrivateKeyBytes());
		assertThrows(SCCException.class, () -> key.getPublicKeyBytes());
		assertThrows(SCCException.class, () -> key.getPrivateKey());
		assertThrows(SCCException.class, () -> key.getPublicKey());

		assertEquals(KeyType.Symmetric, key.getKeyType());
		assertNotEquals(null, key.getAlgorithm());
		assertNotEquals(0, key.getSecretKey().getEncoded().length);
		
		
		// Test key generation algorithm
		assertEquals("AES", key.getAlgorithm());
		SecureCryptoConfig.defaultAlgorithm();

		SCCKey keyAsym = SCCKey.createKey(KeyUseCase.Signing);
		assertEquals(KeyType.Asymmetric, keyAsym.getKeyType());
		assertThrows(SCCException.class, () -> keyAsym.toBytes());
		assertThrows(SCCException.class, () -> keyAsym.getSecretKey());
		assertNotEquals(0, keyAsym.getPrivateKeyBytes().length);
		assertNotEquals(0, keyAsym.getPublicKeyBytes().length);
		assertNotEquals(0, keyAsym.getPrivateKey().getEncoded().length);
		assertNotEquals(0, keyAsym.getPublicKey().getEncoded().length);

	}

	@Test
	void testWrongCipherCreation() throws SCCException {
		assertThrows(SCCException.class, () -> SCCCiphertext.createFromExistingCiphertext("NoCipher".getBytes()));
		assertThrows(SCCException.class, () -> SCCCiphertext.createFromExistingCiphertext("NoCipher".toString()));

	}
	
	@Test
	void testWrongKeyCreation() throws SCCException {
		assertThrows(SCCException.class, () -> SCCKey.createFromExistingKey("NoKey".getBytes()));
	}

	@Test
	void testExistingCipher() throws SCCException {

		String plaintext = "Hello World!";
		SCCKey key = SCCKey.createKey(KeyUseCase.SymmetricEncryption);
		// Encryption
		SCCCiphertext ciphertext = scc.encryptSymmetric(key, plaintext.getBytes());
		String ciphertextString = ciphertext.toBase64();

		SCCCiphertext ciphertext2 = SCCCiphertext.createFromExistingCiphertext(ciphertextString);

		assertEquals(ciphertextString, ciphertext2.toBase64());

	}
	
}
