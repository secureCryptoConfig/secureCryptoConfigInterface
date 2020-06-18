package test;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;


import COSE.CoseException;
import COSE.HashMessage;

import COSE.OneKey;
import COSE.PasswordHashMessage;
import main.PlaintextContainer;
import main.SCCCiphertext;
import main.SCCHash;
import main.SCCKey;
import main.SCCKeyPair;
import main.SCCPasswordHash;
import main.SCCSignature;
import main.SecureCryptoConfig;

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

	//@Test
	void testSCCsymmetricEncryption() throws CoseException {
		PlaintextContainer p = new PlaintextContainer("Hello World");
		SCCKey scckey = SCCKey.createKey(p);
		//SCCKey scckey = SCCKey.createKey();
		SCCCiphertext sccciphertext = scc.symmetricEncrypt(scckey, plaintextContainer);
		//String encryptedPlaintext = sccciphertext.toString();
		PlaintextContainer plain = scc.symmetricDecrypt(scckey, sccciphertext);
		String decrypted = plain.getPlain();
		assertEquals(inputPlaintext, decrypted);

	}
	

	// Test for Hashing / how to test?
	//@Test
	void testHashing() throws CoseException {
		SCCHash hashed = scc.hash(plaintextContainer);
		HashMessage msg = (HashMessage) HashMessage.DecodeFromBytes(hashed.getByteArray());	
		String s = new String(msg.getEncryptedContent(), StandardCharsets.UTF_8);
		SCCHash hashed1 = scc.hash(plaintextContainer);
		HashMessage msg1 = (HashMessage) HashMessage.DecodeFromBytes(hashed1.getByteArray());	
		String s1 = new String(msg1.getEncryptedContent(), StandardCharsets.UTF_8);
		assertEquals(s, s1);
		
	}

	//@Test
	void testSCCasymmetricEncryption() throws CoseException {
		SCCKeyPair pair = SCCKeyPair.createAsymmetricKey();
		
		SCCCiphertext encrypted = scc.asymmetricEncrypt(pair, plaintextContainer);
		PlaintextContainer decrypted = scc.asymmetricDecrypt(pair, encrypted);
		assertEquals(inputPlaintext, decrypted.getPlain());
		
	}

	//@Test
	void testSCCSignature() throws CoseException {
		OneKey k = SCCKeyPair.createSigningKey();
		SCCSignature s = scc.sign(k, plaintextContainer);
		assertEquals(true, scc.validateSignature(k, s));
	}

	// @Test
	void testFileEncryption() throws CoseException {
		String filepath = ".\\src\\main\\Test.txt";
		String fileInput = readFile(filepath).replace("\r", "").replace("\n", "").replace(" ", "");
		SCCKey scckey = SCCKey.createKey();
		SCCCiphertext c = scc.streamEncrypt(scckey, filepath);
		PlaintextContainer p = scc.streamDecrypt(scckey, c, filepath);
		String decrypted = p.getPlain().replace("\r", "").replace("\n", "").replace(" ", "");
		assertEquals(decrypted.equals(fileInput), true);
	}
	

	@Test
	void testPasswordHash() throws CoseException {

		SCCPasswordHash hashed = scc.passwordHash(plaintextContainer);
		PasswordHashMessage msg = (PasswordHashMessage) PasswordHashMessage.DecodeFromBytes(hashed.getByteArray());	
		String s = new String(msg.getEncryptedContent(), StandardCharsets.UTF_8);
		System.out.println(s);
		
		//SCCPasswordHash hashed1 = scc.passwordHash(plaintextContainer);
		//PasswordHashMessage msg1 = (PasswordHashMessage) PasswordHashMessage.DecodeFromBytes(hashed1.getByteArray());	
		//String s1 = new String(msg1.getEncryptedContent(), StandardCharsets.UTF_8);
		//System.out.println(s1);
		//assertEquals(s, s1);
		
	}
	

}
