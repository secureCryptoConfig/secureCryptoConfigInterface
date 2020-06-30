package test;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

import COSE.CoseException;
import main.PlaintextContainer;
import main.SCCHash;
import main.SecureCryptoConfig;

class TestHashing {
	SecureCryptoConfig scc = new SecureCryptoConfig();

	// Use Cases:
	// Hashing (Hashing and PasswordHashing)
	// - byte[] plain hash, return: byte[] hash
	// - String plain hash, return: String hash

	// - byte[] plain hash + validate, return: boolean
	// - String plain hash + validate, return: boolean

	// - hash, return: updated byte[]hash
	// - hash, return: updated String hash

	// Hashing
	// - byte[] plain hash, return: byte[] hash
	@Test
	void testHashingByte() throws CoseException {
		byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
		SCCHash hash = scc.hash(new PlaintextContainer(plaintext));
		byte[] hashedValue = hash.getHashAsPlaintextContainer().getByteArray();

		assertTrue(hashedValue instanceof byte[]);

	}
	
	// - String plain hash, return: String hash
	@Test
	void testHashingString() throws CoseException {
		String plaintext = "Hello World!";
		SCCHash hash = scc.hash(new PlaintextContainer(plaintext.getBytes(StandardCharsets.UTF_8)));
		String hashedValue = hash.getHashAsPlaintextContainer().getString(StandardCharsets.UTF_8);

		assertTrue(hashedValue instanceof String);
	}

	// - byte[] plain hash + validate, return: boolean
	@Test
	void testHashingByteValidation() throws CoseException {
		byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
		SCCHash hash = scc.hash(new PlaintextContainer(plaintext));
		byte[] hashedValue = hash.getHashAsPlaintextContainer().getByteArray();

		boolean result = scc.validateHash(new PlaintextContainer(plaintext), hash);

		assertTrue(result);

	}

	// - String plain hash + validate, return: boolean
	@Test
	void testHashingStringValidation() throws CoseException {
		String plaintext = "Hello World!";
		SCCHash hash = scc.hash(new PlaintextContainer(plaintext.getBytes(StandardCharsets.UTF_8)));
		String hashedValue = hash.getHashAsPlaintextContainer().getString(StandardCharsets.UTF_8);

		boolean result = scc.validateHash(new PlaintextContainer(plaintext.getBytes()), hash);

		assertTrue(result);

	}

	// - hash, return: updated byte[]hash
	@Test
	void testUpdateHashingByte() throws CoseException {
		byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
		SCCHash oldHash = scc.hash(new PlaintextContainer(plaintext));

		SCCHash updatedHash = scc.updateHash(oldHash);
		byte[] newHash = updatedHash.getHashAsPlaintextContainer().getByteArray();

		assertTrue(newHash instanceof byte[]);

	}

	// - hash, return: updated String hash
	@Test
	void testUpdateHashingString() throws CoseException {
		String plaintext = "Hello World!";
		SCCHash oldHash = scc.hash(new PlaintextContainer(plaintext.getBytes(StandardCharsets.UTF_8)));

		SCCHash updatedHash = scc.updateHash(oldHash);
		String newHash = updatedHash.getHashAsString(StandardCharsets.UTF_8);

		assertTrue(newHash instanceof String);
	}
	
	//Password Hashing



}
