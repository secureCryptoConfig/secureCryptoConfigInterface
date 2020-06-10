package test;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;

import org.junit.jupiter.api.Test;

import main.PlaintextContainer;
import main.SCCCiphertext;
import main.SCCHash;
import main.SCCKey;
import main.SCCKeyPair;
import main.SCCSignature;
import main.SecureCryptoConfig;

class SecureCryptoConfigTest {

	SecureCryptoConfig scc = new SecureCryptoConfig();
	String inputPlaintext = "very confidential";
	PlaintextContainer plaintextContainer = new PlaintextContainer(inputPlaintext);
	
	String readFile(String filepath)
	{
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
		SCCKey scckey = SCCKey.createKey();

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
		SCCKeyPair pair = SCCKeyPair.createKeyPair();
		SCCCiphertext encrypted = scc.asymmetricEncrypt(pair, plaintextContainer);
		PlaintextContainer decrypted = scc.asymmetricDecrypt(pair, encrypted);
		assertEquals(inputPlaintext, decrypted.getPlain());
	}

	// @Test
	void testSCCSignature() {
		SCCKeyPair pair = SCCKeyPair.createKeyPair();
		SCCSignature s = scc.sign(pair, plaintextContainer);
		assertEquals(true, scc.validateSignature(pair, s));
	}

	@Test
	void testFileEncryption() {
		String filepath = ".\\src\\main\\Test.txt";
		String fileInput = readFile(filepath).replace("\r", "").replace("\n", "").replace(" ", "");
		SCCKey scckey = SCCKey.createKey();
		SCCCiphertext c = scc.streamEncrypt(scckey, filepath);
		PlaintextContainer p = scc.streamDecrypt(scckey, c, filepath);
		String decrypted = p.getPlain().replace("\r", "").replace("\n", "").replace(" ", "");
		assertEquals(decrypted.equals(fileInput), true);
	}

}
