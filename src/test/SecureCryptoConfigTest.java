package test;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import org.junit.jupiter.api.Test;

import COSE.CoseException;
import COSE.OneKey;
import COSE.Sign1Message;
import main.PlaintextContainer;
import main.PlaintextOutputStream;
import main.SCCCiphertext;
import main.SCCCiphertextOutputStream;
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
	String filepath = ".\\src\\main\\Test.txt";

	@Test
	void testSCCsymmetricEncryption() throws CoseException {
		
		//Key creation with Password
		PlaintextContainer password = new PlaintextContainer("Hello World");
		SCCKey scckey = SCCKey.createKey(password);
		
		//Key creation without a password 
		// SCCKey scckey = SCCKey.createKey();
		
		SCCCiphertext sccciphertext = scc.symmetricEncrypt(scckey, plaintextContainer);
		
		PlaintextContainer plain = scc.symmetricDecrypt(scckey, sccciphertext);
		//PlaintextContainer plain = sccciphertext.symmetricDecrypt(scckey);
	
		assertEquals(inputPlaintext, plain.getString());

	}

	// Test for Hashing -> hash two times same plain
	//@Test
	void testHashing() throws CoseException {
		
		SCCHash hashed = scc.hash(plaintextContainer);
		String hash = hashed.getHashedContent().getString();
		
		SCCHash hashed1 = scc.hash(plaintextContainer);
		String hash2 = hashed1.getHashedContent().getString();
		
		assertEquals(hash, hash2);

	}

	//@Test
	void testSCCasymmetricEncryption() throws CoseException {
		
		SCCKeyPair pair = SCCKeyPair.createAsymmetricKey();

		SCCCiphertext encrypted = scc.asymmetricEncrypt(pair, plaintextContainer);
		PlaintextContainer decrypted = scc.asymmetricDecrypt(pair, encrypted);
		//PlaintextContainer decrypted = encrypted.asymmetricDecrypt(pair);
		
		assertEquals(inputPlaintext, decrypted.getString());

	}

	//@Test
	void testSCCSignature() throws CoseException {
		OneKey k = SCCKeyPair.createSigningKey();
		SCCSignature s = scc.sign(k, plaintextContainer);
		//Sign1Message msg = s.convertByteToMsg();
		//String signature = s.getSignature().getString();
		
		boolean result = scc.validateSignature(k, s);
		//boolean result = s.validateSignature(k);

		assertEquals(true, result);
	}


	//@Test
	void testPasswordHash() throws CoseException {

		SCCPasswordHash hashed = scc.passwordHash(plaintextContainer);

		//String hash = hashed.getHashedContent().getString();

		boolean result = scc.verifyPassword(plaintextContainer, hashed);
		//boolean result = hashed.verifyHash(plaintextContainer);
		
		assertEquals(result, true);

	}
	
	//@Test
	void testFileEncryption() throws NoSuchAlgorithmException, CoseException {
		//retrieve content of file for encryption for later comparison
		String fileInput = UseCases.readFile(filepath).replace("\r", "").replace("\n", "");
		
		SCCKey scckey = SCCKey.createKey();
		SCCCiphertext c = scc.fileEncrypt(scckey, filepath);
		PlaintextContainer p = scc.fileDecrypt(scckey, c, filepath);
		String decrypted = p.getString().replace("\r", "").replace("\n", "");
		
		assertEquals(decrypted.equals(fileInput), true);
	}

	
	//@Test
	void testFileStream() throws NoSuchAlgorithmException, CoseException {
		File file = new File(filepath);
		SCCKey scckey = SCCKey.createKey();
		
		try {
			OutputStream outStream = new FileOutputStream(file);
			SCCCiphertextOutputStream s = scc.streamEncrypt(scckey, outStream);
			
			InputStream fileInputStream = new FileInputStream(filepath);
			PlaintextOutputStream p = scc.streamDecrypt(scckey, s, fileInputStream);
			
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
	}

}
