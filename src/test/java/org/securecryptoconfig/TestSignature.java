package org.securecryptoconfig;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import org.junit.jupiter.api.Test;
import org.securecryptoconfig.SCCKey.KeyUseCase;
import org.securecryptoconfig.SecureCryptoConfig.SCCAlgorithm;

import com.upokecenter.cbor.CBORException;

import COSE.CoseException;

/**
 * Class for testing all functionalities for signing from the Secure Crypto Config Interface
 * @author Lisa
 *
 */
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

	// - byte[] plain sign, return: byte[] signature + new key
	// - byte[] plain sign + validate, return: boolean
	@Test
	void testSigningByteValidation() throws CoseException, NoSuchAlgorithmException, InvalidKeyException, SCCException {
		byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
		SCCKey key = SCCKey.createKey(KeyUseCase.Signing);

		SCCSignature signature = scc.sign(key, plaintext);

		boolean result = scc.validateSignature(key, signature);

		assertTrue(result);

	}

	// - String plain sign, return: String signature + new key
	// - String plain sign + validate, return: boolean
	@Test
	void testSigningStringValidation()
			throws CoseException, NoSuchAlgorithmException, InvalidKeyException, SCCException {
		String plaintext = "Hello World!";
		SCCKey key = SCCKey.createKey(KeyUseCase.Signing);

		SCCSignature signature = scc.sign(key, plaintext.getBytes(StandardCharsets.UTF_8));

		assertTrue(scc.validateSignature(key, signature));
		
		byte[] signatureBytes = signature.toBytes();
		assertTrue(scc.validateSignature(key, signatureBytes));
	}

	// - signature + key, return: updated byte[] signature
	@Test
	void testUpdateSigningByte() throws CoseException, NoSuchAlgorithmException, InvalidKeyException, SCCException {
		byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
		SCCKey key = SCCKey.createKey(KeyUseCase.Signing);

		SCCSignature oldSignature = scc.sign(key, plaintext);
		byte[] oldSignaturebytes = oldSignature.toBytes();

		SCCSignature newSignature = scc.updateSignature(key, plaintext);
		byte[] newSignatureBytes = newSignature.toBytes();
		
		assertTrue(scc.validateSignature(key, oldSignature));
		assertTrue(scc.validateSignature(key, SCCSignature.createFromExistingSignature(oldSignaturebytes)));

		assertTrue(scc.validateSignature(key, newSignature));
		assertTrue(scc.validateSignature(key, SCCSignature.createFromExistingSignature(newSignatureBytes)));

		//Same with short-cut methods
		
		assertTrue(oldSignature.validateSignature(key));
		assertTrue(SCCSignature.createFromExistingSignature(oldSignaturebytes).validateSignature(key));

		assertTrue(newSignature.validateSignature(key));
		assertTrue(SCCSignature.createFromExistingSignature(newSignatureBytes).validateSignature(key));

		byte[] updatedSignatureBytes = oldSignature.updateSignature(new PlaintextContainer(plaintext), key).toBytes();
		assertNotEquals(oldSignaturebytes, updatedSignatureBytes);
	
	}

	// - signature + key, return: updated String signature
	@Test
	void testUpdateSigningString() throws CoseException, NoSuchAlgorithmException, InvalidKeyException, SCCException {
		String plaintext = "Hello World!";
		SCCKey key = SCCKey.createKey(KeyUseCase.Signing);

		SCCSignature oldSignature = scc.sign(key, plaintext.getBytes(StandardCharsets.UTF_8));
		String oldSignatureString = oldSignature.toBase64();

		SCCSignature newSignature = scc.updateSignature(key, plaintext.getBytes(StandardCharsets.UTF_8));
		String newSignatureString = newSignature.toBase64();

		assertTrue(scc.validateSignature(key, oldSignature));
		assertTrue(scc.validateSignature(key, SCCSignature.createFromExistingSignature(oldSignatureString)));

		assertTrue(scc.validateSignature(key, newSignature));
		assertTrue(scc.validateSignature(key, SCCSignature.createFromExistingSignature(newSignatureString)));
	
		//With other String conversion
		String newSignaturetoString = newSignature.toString();
		String oldSignaturetoString = oldSignature.toString();
		
		assertTrue(scc.validateSignature(key, SCCSignature.createFromExistingSignature(oldSignaturetoString)));
		assertTrue(scc.validateSignature(key, SCCSignature.createFromExistingSignature(newSignaturetoString)));
	

	}

	@Test
	void testSigningWithSpecificAlgo() throws SCCException {
		// Set specific algorithm
		SecureCryptoConfig.setAlgorithm(SCCAlgorithm.ECDSA_256);
		
		byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
		SCCKey key = SCCKey.createKey(KeyUseCase.Signing);

		SCCSignature oldSignature = scc.sign(key, plaintext);
		byte[] oldSignaturebytes = oldSignature.toBytes();

		SCCSignature newSignature = scc.updateSignature(key, plaintext);
		byte[] newSignatureBytes = newSignature.toBytes();

		assertTrue(scc.validateSignature(key, oldSignature));
		assertTrue(scc.validateSignature(key, SCCSignature.createFromExistingSignature(oldSignaturebytes)));

		assertTrue(scc.validateSignature(key, newSignature));
		assertTrue(scc.validateSignature(key, SCCSignature.createFromExistingSignature(newSignatureBytes)));
		
		//Other algo
		SecureCryptoConfig.setAlgorithm(SCCAlgorithm.ECDSA_384);
		SCCSignature oldSignature2 = scc.sign(key, plaintext);
		byte[] oldSignaturebytes2 = oldSignature2.toBytes();

		SCCSignature newSignature2 = scc.updateSignature(key, plaintext);
		byte[] newSignatureBytes2 = newSignature.toBytes();

		assertTrue(scc.validateSignature(key, oldSignature2));
		assertTrue(scc.validateSignature(key, SCCSignature.createFromExistingSignature(oldSignaturebytes2)));

		assertTrue(scc.validateSignature(key, newSignature2));
		assertTrue(scc.validateSignature(key, SCCSignature.createFromExistingSignature(newSignatureBytes2)));
		
		SecureCryptoConfig.defaultAlgorithm();
	}
	
	@Test
	void testSigningWithWrongAlgo() throws SCCException {
		
		String plaintext = "Hello World!";
		SCCKey key = SCCKey.createKey(KeyUseCase.Signing);
		
		// Set specific algorithm
		SecureCryptoConfig.setAlgorithm(SCCAlgorithm.AES_GCM_128_96);
		// Sign
		assertThrows(SCCException.class,
				() ->scc.sign(key, plaintext.getBytes(StandardCharsets.UTF_8)));
		
		SecureCryptoConfig.defaultAlgorithm();
	}
	
	@Test
	void testCreateSignature() throws SCCException {
		assertThrows(SCCException.class,
				() ->SCCSignature.createFromExistingSignature("NoSignature".getBytes(StandardCharsets.UTF_8)));
	
		assertThrows(SCCException.class,
				() ->SCCSignature.createFromExistingSignature("NoSignature".toString()));
	
	}
	
	
	@Test
	void testValidatingWithWrongKey() throws SCCException {
		byte[] plaintext = "Hello World".getBytes(StandardCharsets.UTF_8);
		PlaintextContainer p = new PlaintextContainer(plaintext);
		SCCKey signingKey = SCCKey.createKey(KeyUseCase.Signing);
		SCCSignature signature = scc.sign(signingKey, plaintext);
		
		SCCKey wrongKey = SCCKey.createKey(KeyUseCase.SymmetricEncryption);
		assertThrows(SCCException.class,
				() -> scc.validateSignature(wrongKey, signature));
		
		assertThrows(SCCException.class,
				() -> p.validateSignature(signature, wrongKey));

	}
	
}
