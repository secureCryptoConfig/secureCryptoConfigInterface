package test;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;

import org.junit.jupiter.api.Test;

import COSE.CoseException;
import main.SCCKeyPair;
import main.SCCSignature;
import main.SecureCryptoConfig;
import main.SCCKeyPair.keyPairUseCase;

class TestSignature {
	
	SecureCryptoConfig scc = new SecureCryptoConfig();
	
	// Use Cases:
	// Signature
	// - byte[] plain sign, return: byte[] signature + new key
	// - String plain sign, return: String signature + new key

	// - byte[] plain sign + validate, return: boolean
	// - String plain sign + validate, return: boolean

	// - signature + key, return: updated byte[] signature
	// - signature + key, return: updated String signature
	
	
	//- byte[] plain sign, return: byte[] signature + new key
	@Test
	void testSigningByte() throws CoseException, NoSuchAlgorithmException {
		byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
		SCCKeyPair pair = SCCKeyPair.createKeyPair(keyPairUseCase.Signing);
		
		SCCSignature signature = scc.sign(pair, plaintext);
		byte[] s = signature.toBytes();

		assertTrue(s instanceof byte[]);

	}
	
	// - String plain sign, return: String signature + new key
	@Test
	void testSigningString() throws CoseException, NoSuchAlgorithmException {
		String plaintext = "Hello World!";
		SCCKeyPair pair = SCCKeyPair.createKeyPair(keyPairUseCase.Signing);
		
		SCCSignature signature = scc.sign(pair, plaintext.getBytes(StandardCharsets.UTF_8));
		String s = signature.toString(StandardCharsets.UTF_8);
		assertTrue(s instanceof String);
	}

	// - byte[] plain sign + validate, return: boolean
	@Test
	void testSigningByteValidation() throws CoseException, NoSuchAlgorithmException {
		byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
		SCCKeyPair pair = SCCKeyPair.createKeyPair(keyPairUseCase.Signing);
		
		SCCSignature signature = scc.sign(pair,plaintext);
		
		boolean result = scc.validateSignature(signature);

		assertTrue(result);

	}

	// - String plain sign + validate, return: boolean
	@Test
	void testSigningStringValidation() throws CoseException, NoSuchAlgorithmException {
		String plaintext = "Hello World!";
		SCCKeyPair pair = SCCKeyPair.createKeyPair(keyPairUseCase.Signing);
		
		SCCSignature signature = scc.sign(pair, plaintext.getBytes(StandardCharsets.UTF_8));
		
		boolean result = scc.validateSignature(signature);

		assertTrue(result);

	}

	// - signature + key, return: updated byte[] signature
	@Test
	void testUpdateSigningByte() throws CoseException, NoSuchAlgorithmException {
		byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
		SCCKeyPair pair = SCCKeyPair.createKeyPair(keyPairUseCase.Signing);
		
		SCCSignature oldSignature = scc.sign(pair, plaintext);
		
		SCCSignature updatedSignature = scc.updateSignature(oldSignature);
		byte[] newSignature = updatedSignature.toBytes();
		
		assertTrue(newSignature instanceof byte[]);

	}

	// - signature + key, return: updated String signature
	@Test
	void testUpdateSigningString() throws CoseException, NoSuchAlgorithmException {
		String plaintext = "Hello World!";
		SCCKeyPair pair = SCCKeyPair.createKeyPair(keyPairUseCase.Signing);
		
		SCCSignature oldSignature = scc.sign(pair, plaintext.getBytes(StandardCharsets.UTF_8));
		
		SCCSignature updatedSignature = scc.updateSignature(oldSignature);
		String newSignature = updatedSignature.toString(StandardCharsets.UTF_8);
		
		assertTrue(newSignature instanceof String);
	}



}
