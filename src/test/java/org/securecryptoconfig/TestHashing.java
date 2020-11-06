package org.securecryptoconfig;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;
import org.securecryptoconfig.SCCKey.KeyUseCase;
import org.securecryptoconfig.SecureCryptoConfig.SCCAlgorithm;

import com.upokecenter.cbor.CBORException;

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
		//Same with short-cut methods
		assertTrue(new PlaintextContainer(plaintext).validateHash(hash));

		byte[] hashedValue = hash.toBytes();

		assertTrue(scc.validateHash(new PlaintextContainer(plaintext), SCCHash.createFromExistingHash(hashedValue)));
		//Same with short-cut methods
		assertTrue(new PlaintextContainer(plaintext).validateHash(SCCHash.createFromExistingHash(hashedValue)));

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

		//Same with short-cut methods
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
	
	@Test
	void testHashWithSpecificAlgo() throws SCCException {
		// Set specific algorithm
		SecureCryptoConfig.setAlgorithm(SCCAlgorithm.SHA3_512);
		
		String plaintext = "Hello World!";
		PlaintextContainer plaintextContainer = new PlaintextContainer(plaintext.getBytes(StandardCharsets.UTF_8));

		SCCHash hash = plaintextContainer.hash();

		assertTrue(plaintextContainer.validateHash(hash));
	
		SecureCryptoConfig.defaultAlgorithm();
	}
	
	@Test
	void testPasswordHashWithSpecificAlgo() throws SCCException {
		// Set specific algorithm
		SecureCryptoConfig.setAlgorithm(SCCAlgorithm.PBKDF_SHA_256);
		
		String password = "Hello World!";
		SCCPasswordHash hash = scc.passwordHash(password.getBytes(StandardCharsets.UTF_8));
		String hashedValue = hash.toBase64();

		assertTrue(scc.validatePasswordHash(new PlaintextContainer(password.getBytes()), hash));
		assertTrue(scc.validatePasswordHash(new PlaintextContainer(password.getBytes(StandardCharsets.UTF_8)),
				SCCPasswordHash.createFromExistingPasswordHash(hashedValue)));
	
		SecureCryptoConfig.defaultAlgorithm();
	}
	
	@Test
	void testHashWithWrongAlgo() throws SCCException {
		
		String plaintext = "Hello World!";
		
		// Set specific algorithm
		SecureCryptoConfig.setAlgorithm(SCCAlgorithm.ECDSA_256);
		// Encryption
		assertThrows(SCCException.class,
				() ->scc.hash(plaintext.getBytes(StandardCharsets.UTF_8)));
		
		SecureCryptoConfig.defaultAlgorithm();
	}
	
	@Test
	void testPasswordHashWithWrongAlgo() throws SCCException {
		
		String plaintext = "Hello World!";
		
		// Set specific algorithm
		SecureCryptoConfig.setAlgorithm(SCCAlgorithm.ECDSA_256);
		// Encryption
		assertThrows(SCCException.class,
				() ->scc.passwordHash(plaintext.getBytes(StandardCharsets.UTF_8)));
		
		SecureCryptoConfig.defaultAlgorithm();
	}
	
	@Test
	void testCreateHash() throws SCCException {
		assertThrows(CBORException.class,
				() ->SCCHash.createFromExistingHash("NoHash".getBytes()));
	
		assertThrows(CBORException.class,
				() ->SCCHash.createFromExistingHash("NoHash".toString()));
	
	}

}
