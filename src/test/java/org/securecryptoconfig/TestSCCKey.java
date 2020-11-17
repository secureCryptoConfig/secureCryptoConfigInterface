package org.securecryptoconfig;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;
import org.securecryptoconfig.SCCKey.KeyType;
import org.securecryptoconfig.SCCKey.KeyUseCase;
import org.securecryptoconfig.SecureCryptoConfig.SCCAlgorithm;

class TestSCCKey {

	SecureCryptoConfig scc = new SecureCryptoConfig();
	
	// Test crypto primitives with wrong key types
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
	
	// Test if SecreteKey or private/public key can be generated
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
		assertNotEquals(0, key.getSecretKey().getEncoded().length);
		
		SCCKey key2 = SCCKey.createKey(KeyUseCase.SymmetricEncryption);
		assertNotEquals(key2.getSecretKey(), key.getSecretKey());

		// Test key generation algorithm
		assertNotEquals(null, key.getAlgorithm());
		assertEquals("AES", key.getAlgorithm());
		SecureCryptoConfig.defaultAlgorithm();

		//Test methods for asymmetric key (key pair)
		SCCKey keyAsym = SCCKey.createKey(KeyUseCase.Signing);
		assertEquals(KeyType.Asymmetric, keyAsym.getKeyType());
		assertThrows(SCCException.class, () -> keyAsym.toBytes());
		assertThrows(SCCException.class, () -> keyAsym.getSecretKey());
		assertNotEquals(0, keyAsym.getPrivateKeyBytes().length);
		assertNotEquals(0, keyAsym.getPublicKeyBytes().length);
		assertNotEquals(0, keyAsym.getPrivateKey().getEncoded().length);
		assertNotEquals(0, keyAsym.getPublicKey().getEncoded().length);
		
		// Look if details from two keys are different
		SCCKey keyAsym2 = SCCKey.createKey(KeyUseCase.Signing);
		assertNotEquals(keyAsym2.getPrivateKeyBytes(), keyAsym.getPrivateKeyBytes());
		assertNotEquals(keyAsym2.getPublicKeyBytes(), keyAsym.getPublicKeyBytes());
		assertNotEquals(keyAsym2.getPrivateKey(), keyAsym.getPrivateKey());
		assertNotEquals(keyAsym2.getPublicKey(), keyAsym.getPublicKey());

	}
	
	// Test if key of specific type can be created with wrong algorithm
	@Test
	void testSCCKeyWrongAlgo() throws SCCException {
		// Set specific wrong algorithm
		SecureCryptoConfig.setAlgorithm(SCCAlgorithm.ECDSA_256);
		assertThrows(NullPointerException.class, () -> SCCKey.createKey(KeyUseCase.SymmetricEncryption));

		byte[] passwordBytes = "Password".getBytes(StandardCharsets.UTF_8);
		assertThrows(SCCException.class, () -> SCCKey.createSymmetricKeyWithPassword(passwordBytes));
		assertThrows(SCCException.class,
				() -> SCCKey.createSymmetricKeyWithPassword(new PlaintextContainer(passwordBytes)));

		SecureCryptoConfig.setAlgorithm(SCCAlgorithm.AES_GCM_128_96);
		assertThrows(SCCException.class, () -> SCCKey.createKey(KeyUseCase.AsymmetricEncryption));
		assertThrows(SCCException.class, () -> SCCKey.createKey(KeyUseCase.Signing));

		SecureCryptoConfig.defaultAlgorithm();

	}


}
