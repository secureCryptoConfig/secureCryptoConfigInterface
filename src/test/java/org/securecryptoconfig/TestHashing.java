package org.securecryptoconfig;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;
import COSE.CoseException;

/**
 * Class for testing all functionalities for (password) hashing from the Secure Crypto Config Interface
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

		byte[] hashedValue = hash.toBytes();

		assertTrue(scc.validateHash(new PlaintextContainer(plaintext), SCCHash.createFromExistingHash(hashedValue)));

	}

	// - String plain hash, return: String hash
	// - String plain hash + validate, return: boolean
	@Test
	void testHashingStringValidation() throws CoseException, SCCException {
		String plaintext = "Hello World!";
		SCCHash hash = scc.hash(plaintext.getBytes(StandardCharsets.UTF_8));

		assertTrue(scc.validateHash(new PlaintextContainer(plaintext.getBytes()), hash));
		assertTrue(scc.validateHash(new PlaintextContainer(plaintext.getBytes()), SCCHash.createFromExistingHash(hash.toBase64())));
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
		assertTrue(scc.validatePasswordHash(new PlaintextContainer(password), SCCPasswordHash.createFromExistingPasswordHash(hashedValue)));
	}

	// - String plain hash, return: String hash
	// - String plain hash + validate, return: boolean
	@Test
	void testPasswordHashingStringValidation() throws CoseException, SCCException {
		String password = "Hello World!";
		SCCPasswordHash hash = scc.passwordHash(password.getBytes(StandardCharsets.UTF_8));
		String hashedValue = hash.toBase64();

		assertTrue(scc.validatePasswordHash(new PlaintextContainer(password.getBytes()), hash));
		assertTrue(scc.validatePasswordHash(new PlaintextContainer(password.getBytes(StandardCharsets.UTF_8)),
				SCCPasswordHash.createFromExistingPasswordHash(hashedValue)));
	}

}
