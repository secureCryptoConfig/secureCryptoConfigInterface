package org.securecryptoconfig;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;
import org.securecryptoconfig.SecureCryptoConfig.SCCAlgorithm;

import COSE.CoseException;

/**
 * Class for testing all functionalities for (password) hashing from the Secure
 * Crypto Config Interface
 * 
 * @author Lisa
 *
 */
class TestHashing {
	SecureCryptoConfig scc = new SecureCryptoConfig();

	// Use Cases:
	// Hashing
	// - byte[] plain hash, return: byte[] hash
	// - String plain hash, return: String hash

	// - byte[] plain hash + validate, return: boolean
	// - String plain hash + validate, return: boolean

	// - hash, return: updated byte[]hash
	// - hash, return: updated String hash

	// Password Hashing
	// - byte[] plain hash, return: byte[] hash
	// - String plain hash, return: String hash

	// - byte[] plain hash + validate, return: boolean
	// - String plain hash + validate, return: boolean

	// Hashing

	// - byte[] plain hash, return: byte[] hash
	// - byte[] plain hash + validate, return: boolean
	@Test
	void testHashingByteValidation() throws CoseException, SCCException {
		byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
		SCCHash hash = scc.hash(plaintext);

		assertTrue(scc.validateHash(new PlaintextContainer(plaintext), hash));
		assertTrue(scc.validateHash(plaintext, hash));

		// Same with short-cut methods
		assertTrue(new PlaintextContainer(plaintext).validateHash(hash));
		assertTrue(hash.validateHash(plaintext));

		byte[] hashedValue = hash.toBytes();

		assertTrue(scc.validateHash(new PlaintextContainer(plaintext), SCCHash.createFromExistingHash(hashedValue)));
		// Same with short-cut methods
		assertTrue(new PlaintextContainer(plaintext).validateHash(SCCHash.createFromExistingHash(hashedValue)));
		assertTrue(SCCHash.createFromExistingHash(hashedValue).validateHash(plaintext));

	}

	// - String plain hash, return: String hash
	// - String plain hash + validate, return: boolean
	@Test
	void testHashingStringValidation() throws CoseException, SCCException {
		String plaintext = "Hello World!";
		SCCHash hash = scc.hash(plaintext.getBytes(StandardCharsets.UTF_8));

		assertTrue(scc.validateHash(new PlaintextContainer(plaintext.getBytes(StandardCharsets.UTF_8)), hash));
		assertTrue(scc.validateHash(new PlaintextContainer(plaintext.getBytes(StandardCharsets.UTF_8)),
				SCCHash.createFromExistingHash(hash.toBase64())));

		// Same with other String conversion
		assertTrue(scc.validateHash(new PlaintextContainer(plaintext.getBytes(StandardCharsets.UTF_8)),
				SCCHash.createFromExistingHash(hash.toString())));

	}

	// - hash, return: updated byte[]hash
	@Test
	void testUpdateHashingByte() throws CoseException, SCCException {
		byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);

		// TODO here we should change the actually used hash to test if
		// rehashing/updating hash works correctly.

		SCCHash oldHash = scc.hash(plaintext);
		byte[] oldHashBytes = oldHash.toBytes();

		SCCHash newHash = scc.updateHash(plaintext, oldHash);
		byte[] newHashBytes = newHash.toBytes();

		assertTrue(scc.validateHash(new PlaintextContainer(plaintext), oldHash));
		assertTrue(scc.validateHash(new PlaintextContainer(plaintext), SCCHash.createFromExistingHash(oldHashBytes)));
		assertTrue(scc.validateHash(new PlaintextContainer(plaintext), newHash));
		assertTrue(scc.validateHash(new PlaintextContainer(plaintext), SCCHash.createFromExistingHash(newHashBytes)));

		// Same with short-cut methods
		SCCHash oldHash2 = new PlaintextContainer(plaintext).hash();
		byte[] oldHashBytes2 = oldHash2.toBytes();

		SCCHash newHash2 = (SCCHash) oldHash2.updateHash(plaintext);
		byte[] newHashBytes2 = newHash2.toBytes();

		assertTrue(scc.validateHash(new PlaintextContainer(plaintext), oldHash2));
		assertTrue(scc.validateHash(new PlaintextContainer(plaintext), SCCHash.createFromExistingHash(oldHashBytes2)));
		assertTrue(scc.validateHash(new PlaintextContainer(plaintext), newHash2));
		assertTrue(scc.validateHash(new PlaintextContainer(plaintext), SCCHash.createFromExistingHash(newHashBytes2)));

	}

	// - hash, return: updated String hash
	@Test
	void testUpdateHashingString() throws CoseException, SCCException {
		String plaintext = "Hello World!";
		SCCHash oldHash = scc.hash(plaintext.getBytes(StandardCharsets.UTF_8));
		String oldHashString = oldHash.toBase64();

		SCCHash newHash = scc.updateHash(plaintext.getBytes(), oldHash);
		String newHashString = newHash.toBase64();

		assertTrue(scc.validateHash(new PlaintextContainer(plaintext.getBytes(StandardCharsets.UTF_8)), oldHash));
		assertTrue(scc.validateHash(new PlaintextContainer(plaintext.getBytes(StandardCharsets.UTF_8)), newHash));
		assertTrue(scc.validateHash(new PlaintextContainer(plaintext.getBytes(StandardCharsets.UTF_8)),
				SCCHash.createFromExistingHash(oldHashString)));
		assertTrue(scc.validateHash(new PlaintextContainer(plaintext.getBytes(StandardCharsets.UTF_8)),
				SCCHash.createFromExistingHash(newHashString)));

	}

	// - PlaintextContainer hash, return: String hash
	// - PlaintextContainer + validate, return: boolean
	@Test
	void testPlaintextContainerHashing() throws SCCException {
		String plaintext = "Hello World!";
		PlaintextContainer plaintextContainer = new PlaintextContainer(plaintext.getBytes(StandardCharsets.UTF_8));

		SCCHash hash = plaintextContainer.hash();

		assertTrue(plaintextContainer.validateHash(hash));
	}

	// Password Hashing

	// - byte[] plain hash, return: byte[] hash
	// - byte[] plain hash + validate, return: boolean
	@Test
	void testPasswordHashingByteValidation() throws CoseException, SCCException {
		byte[] password = "Hello World!".getBytes(StandardCharsets.UTF_8);
		SCCPasswordHash hash = scc.passwordHash(password);
		byte[] hashedValue = hash.toBytes();

		assertTrue(scc.validatePasswordHash(new PlaintextContainer(password), hash));
		assertTrue(scc.validatePasswordHash(password, hash));

		assertTrue(scc.validatePasswordHash(new PlaintextContainer(password),
				SCCPasswordHash.createFromExistingPasswordHash(hashedValue)));

		// Same with short-cut methods
		assertTrue(hash.validatePasswordHash(password));
		assertTrue(SCCPasswordHash.createFromExistingPasswordHash(hashedValue)
				.validatePasswordHash(new PlaintextContainer(password)));

	}

	// - String plain hash, return: String hash
	// - String plain hash + validate, return: boolean
	@Test
	void testPasswordHashingStringValidation() throws CoseException, SCCException {
		String password = "Hello World!";
		SCCPasswordHash hash = scc.passwordHash(password.getBytes(StandardCharsets.UTF_8));
		String hashedValue = hash.toBase64();

		assertTrue(scc.validatePasswordHash(new PlaintextContainer(password.getBytes(StandardCharsets.UTF_8)), hash));
		assertTrue(scc.validatePasswordHash(new PlaintextContainer(password.getBytes(StandardCharsets.UTF_8)),
				SCCPasswordHash.createFromExistingPasswordHash(hashedValue)));

		// Same with other String conversion
		String hashedValueString = hash.toString();

		assertTrue(scc.validatePasswordHash(new PlaintextContainer(password.getBytes(StandardCharsets.UTF_8)),
				SCCPasswordHash.createFromExistingPasswordHash(hashedValueString)));

	}

	// Test if hashing is possible with specific algo
	@Test
	void testHashWithSpecificAlgo() throws SCCException {
		// Set specific algorithm
		SecureCryptoConfig.setAlgorithm(SCCAlgorithm.SHA3_512);

		String plaintext = "Hello World!";
		PlaintextContainer plaintextContainer = new PlaintextContainer(plaintext.getBytes(StandardCharsets.UTF_8));

		SCCHash hash = plaintextContainer.hash();

		assertTrue(plaintextContainer.validateHash(hash));

		// Other Algo
		SecureCryptoConfig.setAlgorithm(SCCAlgorithm.SHA3_256);
		SCCHash hash2 = plaintextContainer.hash();

		assertTrue(plaintextContainer.validateHash(hash2));

		// Other Algo
		SecureCryptoConfig.setAlgorithm(SCCAlgorithm.SHA_256);
		SCCHash hash3 = plaintextContainer.hash();

		assertTrue(plaintextContainer.validateHash(hash3));

		SecureCryptoConfig.defaultAlgorithm();
	}

	// Test if password hashing is possible with specific algo
	@Test
	void testPasswordHashWithSpecificAlgo() throws SCCException {
		// Set specific algorithm
		SecureCryptoConfig.setAlgorithm(SCCAlgorithm.PBKDF_SHA_512);

		String password = "Hello World!";
		SCCPasswordHash hash = scc.passwordHash(password.getBytes(StandardCharsets.UTF_8));
		String hashedValue = hash.toBase64();

		assertTrue(scc.validatePasswordHash(new PlaintextContainer(password.getBytes(StandardCharsets.UTF_8)), hash));
		assertTrue(scc.validatePasswordHash(new PlaintextContainer(password.getBytes(StandardCharsets.UTF_8)),
				SCCPasswordHash.createFromExistingPasswordHash(hashedValue)));

		//Other algo
		SecureCryptoConfig.setAlgorithm(SCCAlgorithm.SHA_512_64);
		SCCPasswordHash hash2 = scc.passwordHash(password.getBytes(StandardCharsets.UTF_8));
		String hashedValue2 = hash2.toBase64();

		assertTrue(scc.validatePasswordHash(new PlaintextContainer(password.getBytes(StandardCharsets.UTF_8)), hash2));
		assertTrue(scc.validatePasswordHash(new PlaintextContainer(password.getBytes(StandardCharsets.UTF_8)),
				SCCPasswordHash.createFromExistingPasswordHash(hashedValue2)));


		
		SecureCryptoConfig.defaultAlgorithm();
	}
	
	// Test if hashing is possible with wrong algo
	@Test
	void testHashWithWrongAlgo() throws SCCException {

		String plaintext = "Hello World!";

		// Set specific algorithm
		SecureCryptoConfig.setAlgorithm(SCCAlgorithm.ECDSA_256);
		// Encryption
		assertThrows(SCCException.class, () -> scc.hash(plaintext.getBytes(StandardCharsets.UTF_8)));

		SecureCryptoConfig.defaultAlgorithm();
	}

	// Test if password hashing is possible with wrong algo
	@Test
	void testPasswordHashWithWrongAlgo() throws SCCException {

		String plaintext = "Hello World!";

		// Set specific algorithm
		SecureCryptoConfig.setAlgorithm(SCCAlgorithm.ECDSA_256);
		// Encryption
		assertThrows(SCCException.class, () -> scc.passwordHash(plaintext.getBytes(StandardCharsets.UTF_8)));

		SecureCryptoConfig.defaultAlgorithm();
	}

	// Test if not correct byte[] hash can be used to generate a SCCHash
	@Test
	void testCreateHash() throws SCCException {
		assertThrows(SCCException.class, () -> SCCHash.createFromExistingHash("NoHash".getBytes(StandardCharsets.UTF_8)));

		assertThrows(SCCException.class, () -> SCCHash.createFromExistingHash("NoHash".toString()));

	}

	// Test if not correct byte[] hash can be used to generate a SCCPasswordHash
	@Test
	void testCreatePasswordHash() throws SCCException {
		assertThrows(SCCException.class, () -> SCCPasswordHash.createFromExistingPasswordHash("NoHash".getBytes(StandardCharsets.UTF_8)));

		assertThrows(SCCException.class, () -> SCCPasswordHash.createFromExistingPasswordHash("NoHash".toString()));

	}

}
