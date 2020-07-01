package test;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

import COSE.CoseException;
import main.PlaintextContainer;
import main.SCCHash;
import main.SCCPasswordHash;
import main.SecureCryptoConfig;

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
	
	//Password Hashing
	// - byte[] plain hash, return: byte[] hash
	// - String plain hash, return: String hash

	// - byte[] plain hash + validate, return: boolean
	// - String plain hash + validate, return: boolean

	// Hashing
	// - byte[] plain hash, return: byte[] hash
	@Test
	void testHashingByte() throws CoseException {
		byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
		SCCHash hash = scc.hash(plaintext);
		byte[] hashedValue = hash.getHashBytes();

		assertTrue(hashedValue instanceof byte[]);

	}
	
	// - String plain hash, return: String hash
	@Test
	void testHashingString() throws CoseException {
		String plaintext = "Hello World!";
		SCCHash hash = scc.hash(plaintext.getBytes(StandardCharsets.UTF_8));
		String hashedValue = hash.getHashAsString(StandardCharsets.UTF_8);
		assertTrue(hashedValue instanceof String);
	}

	// - byte[] plain hash + validate, return: boolean
	@Test
	void testHashingByteValidation() throws CoseException {
		byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
		SCCHash hash = scc.hash(plaintext);
		byte[] hashedValue = hash.getHashBytes();

		boolean result = scc.validateHash(new PlaintextContainer(plaintext), hash);

		assertTrue(result);

	}

	// - String plain hash + validate, return: boolean
	@Test
	void testHashingStringValidation() throws CoseException {
		String plaintext = "Hello World!";
		SCCHash hash = scc.hash(plaintext.getBytes(StandardCharsets.UTF_8));
		String hashedValue = hash.getHashAsString(StandardCharsets.UTF_8);
				
		boolean result = scc.validateHash(new PlaintextContainer(plaintext.getBytes()), hash);

		assertTrue(result);

	}

	// - hash, return: updated byte[]hash
	@Test
	void testUpdateHashingByte() throws CoseException {
		byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
		SCCHash oldHash = scc.hash(plaintext);

		SCCHash updatedHash = scc.updateHash(oldHash);
		byte[] newHash = updatedHash.getHashBytes();

		assertTrue(newHash instanceof byte[]);

	}

	// - hash, return: updated String hash
	@Test
	void testUpdateHashingString() throws CoseException {
		String plaintext = "Hello World!";
		SCCHash oldHash = scc.hash(plaintext.getBytes(StandardCharsets.UTF_8));

		SCCHash updatedHash = scc.updateHash(oldHash);
		String newHash = updatedHash.getHashAsString(StandardCharsets.UTF_8);

		assertTrue(newHash instanceof String);
	}
	
	//Password Hashing
	
	// - byte[] plain hash, return: byte[] hash
		@Test
		void testPasswordHashingByte() throws CoseException {
			byte[] password = "Hello World!".getBytes(StandardCharsets.UTF_8);
			SCCPasswordHash hash = scc.passwordHash(password);
			byte[] hashedValue = hash.getHashBytes();

			assertTrue(hashedValue instanceof byte[]);

		}
		
		// - String plain hash, return: String hash
		@Test
		void testPasswordHashingString() throws CoseException {
			String password = "Hello World!";
			SCCPasswordHash hash = scc.passwordHash(password.getBytes(StandardCharsets.UTF_8));
			String hashedValue = hash.getHashAsString(StandardCharsets.UTF_8);
			
			assertTrue(hashedValue instanceof String);
		}

		// - byte[] plain hash + validate, return: boolean
		@Test
		void testPasswordHashingByteValidation() throws CoseException {
			byte[] password = "Hello World!".getBytes(StandardCharsets.UTF_8);
			SCCPasswordHash hash = scc.passwordHash(password);
			byte[] hashedValue = hash.getHashBytes();

			boolean result = scc.validatePasswordHash(new PlaintextContainer(password), hash);

			assertTrue(result);

		}

		// - String plain hash + validate, return: boolean
		@Test
		void testPasswordHashingStringValidation() throws CoseException {
			String password = "Hello World!";
			SCCPasswordHash hash = scc.passwordHash(password.getBytes(StandardCharsets.UTF_8));
			String hashedValue = hash.getHashAsString(StandardCharsets.UTF_8);
			boolean result = scc.validatePasswordHash(new PlaintextContainer(password.getBytes()), hash);

			assertTrue(result);

		}


}
