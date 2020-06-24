package test;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import org.junit.jupiter.api.Test;

import COSE.CoseException;
import COSE.HashMessage;
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

	// @Test
	void testSCCsymmetricEncryption() throws CoseException {
		PlaintextContainer p = new PlaintextContainer("Hello World");
		SCCKey scckey = SCCKey.createKey(p);
		// SCCKey scckey = SCCKey.createKey();
		SCCCiphertext sccciphertext = scc.symmetricEncrypt(scckey, plaintextContainer);
		// String encryptedPlaintext = sccciphertext.toString();
		PlaintextContainer plain = scc.symmetricDecrypt(scckey, sccciphertext);
		String decrypted = plain.getString();
		assertEquals(inputPlaintext, decrypted);

	}

	// Test for Hashing / how to test?
	// @Test
	void testHashing() throws CoseException {
		SCCHash hashed = scc.hash(plaintextContainer);
		HashMessage msg = (HashMessage) HashMessage.DecodeFromBytes(hashed.getMessageBytes());
		String s = Base64.getEncoder().encodeToString(msg.getHashedContent());
		SCCHash hashed1 = scc.hash(plaintextContainer);
		HashMessage msg1 = (HashMessage) HashMessage.DecodeFromBytes(hashed1.getMessageBytes());
		String s1 = Base64.getEncoder().encodeToString(msg1.getHashedContent());
		assertEquals(s, s1);

	}

	// @Test
	void testSCCasymmetricEncryption() throws CoseException {
		SCCKeyPair pair = SCCKeyPair.createAsymmetricKey();

		SCCCiphertext encrypted = scc.asymmetricEncrypt(pair, plaintextContainer);
		PlaintextContainer decrypted = scc.asymmetricDecrypt(pair, encrypted);
		assertEquals(inputPlaintext, decrypted.getString());

	}

	// @Test
	void testSCCSignature() throws CoseException {
		OneKey k = SCCKeyPair.createSigningKey();
		SCCSignature s = scc.sign(k, plaintextContainer);
		Sign1Message msg = (Sign1Message) Sign1Message.DecodeFromBytes(s.getMessageBytes());
		String signature = Base64.getEncoder().encodeToString(msg.getSignature());
		System.out.println(signature);

		assertEquals(true, scc.validateSignature(k, s));
	}

	// @Test
	void testFileEncryption() throws NoSuchAlgorithmException, CoseException {
		String fileInput = UseCases.readFile(filepath).replace("\r", "").replace("\n", "");
		SCCKey scckey = SCCKey.createKey();
		SCCCiphertext c = scc.fileEncrypt(scckey, filepath);
		PlaintextContainer p = scc.fileDecrypt(scckey, c, filepath);
		String decrypted = p.getString().replace("\r", "").replace("\n", "");
		System.out.println(fileInput);
		System.out.println(decrypted);
		assertEquals(decrypted.equals(fileInput), true);
	}

	@Test
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

	// @Test
	void testPasswordHash() throws CoseException {

		SCCPasswordHash hashed = scc.passwordHash(plaintextContainer);
		// PasswordHashMessage msg = (PasswordHashMessage)
		// PasswordHashMessage.DecodeFromBytes(hashed.getByteArray());
		// String s = new String(msg.GetContent(), StandardCharsets.UTF_8);

		assertEquals(scc.verifyPassword(plaintextContainer, hashed), true);

	}

}
