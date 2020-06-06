package test;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import javax.crypto.SecretKey;

import org.junit.jupiter.api.Test;

import com.upokecenter.cbor.CBORObject;

import COSE.Attribute;
import COSE.CoseException;
import COSE.Encrypt0Message;
import COSE.HeaderKeys;
import main.PlaintextContainer;
import main.SCCCiphertext;
import main.SCCHash;
import main.SCCKey;
import main.SCCKeyPair;
import main.SecureCryptoConfig;
import main.UseCases;

class SecureCryptoConfigTest {

	SecureCryptoConfig scc = new SecureCryptoConfig();
	String inputPlaintext = "very confidential";
	PlaintextContainer plaintextContainer = new PlaintextContainer(inputPlaintext);

	//@Test
	void testSCCsymmetricEncryption() {
		SCCKey scckey = SCCKey.createKey();

		SCCCiphertext sccciphertext = scc.symmetricEncrypt(scckey, plaintextContainer);
		//String encryptedPlaintext = sccciphertext.toString();
		PlaintextContainer plain = scc.symmetricDecrypt(scckey, sccciphertext);
		String decrypted = plain.getPlain();
		assertEquals(inputPlaintext, decrypted);

	}

	// Test for Hashing / how to test?
	//@Test
	void testHashing() {
		SCCHash hashed = scc.hash(plaintextContainer);
		String s = hashed.toString();
		SCCHash hashed1 = scc.hash(plaintextContainer);
		String s1 = hashed1.toString();
		assertEquals(s, s1);
	}
	
	//@Test
	void testSCCasymmetricEncryption(){
		SCCKeyPair pair = SCCKeyPair.createKeyPair();
		SCCCiphertext encrypted = scc.asymmetricEncrypt(pair, plaintextContainer);
		System.out.println(encrypted.toString());
		assertEquals(1,1);
	}
	@Test
	void message() {
		String nonce = "NONCE";
		String algo ="AES";
		Encrypt0Message o = new Encrypt0Message();
		o.SetContent("Confidential");
		CBORObject ob = CBORObject.FromObject(32);
		CBORObject n = CBORObject.FromObject(nonce);
		try {
			o.addAttribute(n, ob, Attribute.PROTECTED);
			o.addAttribute(HeaderKeys.Algorithm, CBORObject.FromObject(algo), Attribute.PROTECTED);
		} catch (CoseException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		//CBORObject algX = findA;
		System.out.println(o.findAttribute(HeaderKeys.Algorithm));
		System.out.println(o.getProtectedAttributes());
		System.out.println(o.findAttribute(n));
		assertEquals(1, 1);
	}

}
