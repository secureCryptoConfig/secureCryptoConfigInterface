package test;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;
import org.securecryptoconfig.PlaintextContainer;
import org.securecryptoconfig.SCCHash;
import org.securecryptoconfig.SCCPasswordHash;
import org.securecryptoconfig.SecureCryptoConfig;

import COSE.CoseException;

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
	void testHashingByteValidation() throws CoseException {
		byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
		SCCHash hash = scc.hash(plaintext);

		assertTrue(scc.validateHash(new PlaintextContainer(plaintext), hash));

		byte[] hashedValue = hash.toBytes();

		assertTrue(scc.validateHash(new PlaintextContainer(plaintext), new SCCHash(hashedValue)));

	}

	// - String plain hash, return: String hash
	// - String plain hash + validate, return: boolean
	@Test
	void testHashingStringValidation() throws CoseException {
		String plaintext = "Hello World!";
		SCCHash hash = scc.hash(plaintext.getBytes(StandardCharsets.UTF_8));

		assertTrue(scc.validateHash(new PlaintextContainer(plaintext.getBytes()), hash));
		assertTrue(scc.validateHash(new PlaintextContainer(plaintext.getBytes()), new SCCHash(hash.toString())));
	}

	// - hash, return: updated byte[]hash
	@Test
	void testUpdateHashingByte() throws CoseException {
		byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);

		// TODO here we should change the actually used hash to test if
		// rehashing/updating hash works correctly.

		SCCHash oldHash = scc.hash(plaintext);
		byte[] oldHashBytes = oldHash.toBytes();

		SCCHash newHash = scc.updateHash(plaintext, oldHash);
		byte[] newHashBytes = newHash.toBytes();

		assertTrue(scc.validateHash(new PlaintextContainer(plaintext), oldHash));
		assertTrue(scc.validateHash(new PlaintextContainer(plaintext), new SCCHash(oldHashBytes)));
		assertTrue(scc.validateHash(new PlaintextContainer(plaintext), newHash));
		assertTrue(scc.validateHash(new PlaintextContainer(plaintext), new SCCHash(newHashBytes)));

	}

	// - hash, return: updated String hash
	@Test
	void testUpdateHashingString() throws CoseException {
		String plaintext = "Hello World!";
		SCCHash oldHash = scc.hash(plaintext.getBytes(StandardCharsets.UTF_8));
		String oldHashString = oldHash.toString();

		SCCHash newHash = scc.updateHash(plaintext.getBytes(), oldHash);
		String newHashString = newHash.toString();

		assertTrue(scc.validateHash(new PlaintextContainer(plaintext.getBytes(StandardCharsets.UTF_8)), oldHash));
		assertTrue(scc.validateHash(new PlaintextContainer(plaintext.getBytes(StandardCharsets.UTF_8)), newHash));
		assertTrue(scc.validateHash(new PlaintextContainer(plaintext.getBytes(StandardCharsets.UTF_8)),
				new SCCHash(oldHashString)));
		assertTrue(scc.validateHash(new PlaintextContainer(plaintext.getBytes(StandardCharsets.UTF_8)),
				new SCCHash(newHashString)));

	}

	// Password Hashing

	// - byte[] plain hash, return: byte[] hash
	// - byte[] plain hash + validate, return: boolean
	@Test
	void testPasswordHashingByteValidation() throws CoseException {
		byte[] password = "Hello World!".getBytes(StandardCharsets.UTF_8);
		SCCPasswordHash hash = scc.passwordHash(password);
		byte[] hashedValue = hash.toBytes();

		boolean result = scc.validatePasswordHash(new PlaintextContainer(password), hash);

		assertTrue(result);

	}

	// - String plain hash, return: String hash
	// - String plain hash + validate, return: boolean
	@Test
	void testPasswordHashingStringValidation() throws CoseException {
		String password = "Hello World!";
		SCCPasswordHash hash = scc.passwordHash(password.getBytes(StandardCharsets.UTF_8));
		String hashedValue = hash.toString(StandardCharsets.UTF_8);
		boolean result = scc.validatePasswordHash(new PlaintextContainer(password.getBytes()), hash);

		assertTrue(result);

	}

}
