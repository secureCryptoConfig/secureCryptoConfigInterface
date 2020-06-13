package test;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;

import org.junit.jupiter.api.Test;

import main.JSONReader.CryptoUseCase;
import main.PlaintextContainer;
import main.SCCCiphertext;
import main.SCCHash;
import main.SCCKey;
import main.SCCKeyPair;
import main.SCCPasswordHash;
import main.SCCSignature;
import main.SecureCryptoConfig;
import main.UseCases;

class SecureCryptoConfigTest {

	SecureCryptoConfig scc = new SecureCryptoConfig();
	String inputPlaintext = "very confidential";
	PlaintextContainer plaintextContainer = new PlaintextContainer(inputPlaintext);

	// Method for getting file content. Content needed for comparing file encryption
	// test
	String readFile(String filepath) {
		String s = "";
		try {
			File file = new File(filepath);
			BufferedReader br = new BufferedReader(new FileReader(file));
			String st;
			while ((st = br.readLine()) != null) {
				s = s + st + "\n";
			}
			br.close();
			return s;
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}

	// @Test
	void testSCCsymmetricEncryption() {
		PlaintextContainer p = new PlaintextContainer("Hello World");
		SCCKey scckey = SCCKey.createKey(p);

		// SCCKey scckey = SCCKey.createKey();
		SCCCiphertext sccciphertext = scc.symmetricEncrypt(scckey, plaintextContainer);
		// String encryptedPlaintext = sccciphertext.toString();
		PlaintextContainer plain = scc.symmetricDecrypt(scckey, sccciphertext);
		String decrypted = plain.getPlain();
		assertEquals(inputPlaintext, decrypted);

	}

	// Test for Hashing / how to test?
	// @Test
	void testHashing() {
		SCCHash hashed = scc.hash(plaintextContainer);
		String s = hashed.toString();
		SCCHash hashed1 = scc.hash(plaintextContainer);
		String s1 = hashed1.toString();
		assertEquals(s, s1);
	}

	// @Test
	void testSCCasymmetricEncryption() {
		SCCKeyPair pair = SCCKeyPair.createKeyPair(CryptoUseCase.AsymmetricEncryption);
		SCCCiphertext encrypted = scc.asymmetricEncrypt(pair, plaintextContainer);
		PlaintextContainer decrypted = scc.asymmetricDecrypt(pair, encrypted);
		assertEquals(inputPlaintext, decrypted.getPlain());
	}

	// @Test
	void testSCCSignature() {
		SCCKeyPair pair = SCCKeyPair.createKeyPair(CryptoUseCase.Signing);
		SCCSignature s = scc.sign(pair, plaintextContainer);
		assertEquals(true, scc.validateSignature(pair, s));
	}

	// @Test
	void testFileEncryption() {
		String filepath = ".\\src\\main\\Test.txt";
		String fileInput = readFile(filepath).replace("\r", "").replace("\n", "").replace(" ", "");
		SCCKey scckey = SCCKey.createKey();
		SCCCiphertext c = scc.streamEncrypt(scckey, filepath);
		PlaintextContainer p = scc.streamDecrypt(scckey, c, filepath);
		String decrypted = p.getPlain().replace("\r", "").replace("\n", "").replace(" ", "");
		assertEquals(decrypted.equals(fileInput), true);
	}

	@Test
	void testPasswordHash() {

		SCCPasswordHash hash = scc.passwordHash(plaintextContainer);
		SCCPasswordHash hash1 = UseCases.passwordHashing(plaintextContainer, hash.getAlgo(), hash.getSalt(),
				hash.getKeySize(), hash.getIterations());
		assertEquals(hash.toString().equals(hash1.toString()), true);

	}
}
