package main;

import java.nio.charset.Charset;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import COSE.CoseException;
import main.SCCKey.SCCKeyAlgorithm;

abstract interface SecureCryptoConfigInterface {

	// Symmetric Encryption
	public AbstractSCCCiphertext encryptSymmetric(AbstractSCCKey key, PlaintextContainerInterface plaintext)
			throws CoseException;

	public AbstractSCCCiphertext encryptSymmetric(AbstractSCCKey key, byte[] plaintext) throws CoseException;

	public AbstractSCCCiphertext reEncryptSymmetric(AbstractSCCKey key, AbstractSCCCiphertext ciphertext)
			throws CoseException;

	public PlaintextContainerInterface decryptSymmetric(AbstractSCCKey key, AbstractSCCCiphertext sccciphertext)
			throws CoseException;

	// File encryption working with Streams
	/*
	public AbstractSCCCiphertextOutputStream encryptStream(AbstractSCCKey key, InputStream inputStream)
			throws NoSuchAlgorithmException;

	public AbstractPlaintextOutputStream decryptStream(AbstractSCCKey key,
			AbstractSCCCiphertextOutputStream outputStream, InputStream inputStream);
	*/
	
	// Simple File encryption
	public AbstractSCCCiphertext encryptFile(AbstractSCCKey key, String filepath) throws NoSuchAlgorithmException;

	public PlaintextContainerInterface decryptFile(AbstractSCCKey key, AbstractSCCCiphertext ciphertext,
			String filepath);

	// Asymmetric
	public AbstractSCCCiphertext encryptAsymmetric(AbstractSCCKeyPair keyPair, PlaintextContainerInterface plaintext)
			throws CoseException;

	public AbstractSCCCiphertext encryptAsymmetric(AbstractSCCKeyPair keyPair, byte[] plaintext) throws CoseException;

	public AbstractSCCCiphertext reEncryptAsymmetric(AbstractSCCKeyPair keyPair, AbstractSCCCiphertext ciphertext)
			throws CoseException;

	public PlaintextContainerInterface decryptAsymmetric(AbstractSCCKeyPair keyPair, AbstractSCCCiphertext ciphertext)
			throws CoseException;

	// Hashing
	public AbstractSCCHash hash(PlaintextContainerInterface plaintext) throws CoseException;

	public AbstractSCCHash hash(byte[] plaintext) throws CoseException;

	public AbstractSCCHash updateHash(AbstractSCCHash hash) throws CoseException;

	public boolean validateHash(PlaintextContainerInterface plaintext, AbstractSCCHash hash) throws CoseException;

	public boolean validateHash(byte[] plaintext, AbstractSCCHash hash) throws CoseException;

	// Digital Signature
	public AbstractSCCSignature sign(AbstractSCCKeyPair key, PlaintextContainerInterface plaintext)
			throws CoseException;

	public AbstractSCCSignature sign(AbstractSCCKeyPair key, byte[] plaintext) throws CoseException;

	public AbstractSCCSignature updateSignature(AbstractSCCSignature signature)
			throws CoseException;

	public boolean validateSignature(AbstractSCCSignature signature);

	// Password Hashing
	public AbstractSCCPasswordHash passwordHash(PlaintextContainerInterface password) throws CoseException;

	public AbstractSCCPasswordHash passwordHash(byte[] password) throws CoseException;

	public boolean validatePasswordHash(PlaintextContainerInterface password, AbstractSCCPasswordHash passwordhash)
			throws CoseException;

	public boolean validatePasswordHash(byte[] password, AbstractSCCPasswordHash passwordhash)
			throws CoseException;
}

abstract interface PlaintextContainerInterface {

	abstract byte[] toBytes();

	abstract String toString(Charset c);

	abstract boolean validateHash(AbstractSCCHash hash);

	abstract boolean validatePasswordHash(AbstractSCCPasswordHash passwordHash);

	abstract SCCCiphertext encryptSymmetric(AbstractSCCKey key);

	abstract SCCCiphertext encryptAsymmetric(AbstractSCCKeyPair pair);

	abstract SCCSignature sign(AbstractSCCKeyPair keyPair);

	abstract SCCHash hash();

	abstract SCCPasswordHash passwordHash();

}

abstract class AbstractSCCCiphertext {
	byte[] msg;

	public AbstractSCCCiphertext(byte[] msg) {
		this.msg = msg;
	}

	abstract byte[] toBytes();

	abstract String toString(Charset c);

	abstract PlaintextContainer decryptAsymmetric(AbstractSCCKeyPair keyPair);

	abstract PlaintextContainer decryptSymmetric(AbstractSCCKey key);

	abstract SCCCiphertext reEncryptSymmetric(AbstractSCCKey key);

	abstract SCCCiphertext reEncryptAsymmetric(AbstractSCCKeyPair keyPair);

}

abstract class AbstractSCCKey {

	byte[] key;
	SCCKeyAlgorithm algorithm;

	protected AbstractSCCKey(byte[] key, SCCKeyAlgorithm algorithm) {
		this.key = key;
		this.algorithm = algorithm;

	}

	abstract byte[] toBytes();

}

abstract class AbstractSCCKeyPair {
	KeyPair pair;

	protected AbstractSCCKeyPair(KeyPair pair) {
		this.pair = pair;
	}

	abstract byte[] getPublicKeyBytes();

	abstract byte[] getPrivateKeyBytes();

}

abstract class AbstractSCCHash {

	byte[] hashMsg;
	PlaintextContainerInterface plaintext;

	public AbstractSCCHash(PlaintextContainerInterface plaintext, byte[] hashMsg) {
		this.plaintext = plaintext;
		this.hashMsg = hashMsg;
	}

	abstract byte[] toBytes();
	
	abstract String toString(Charset c);
	
	abstract boolean validateHash(PlaintextContainerInterface plaintext);

	abstract SCCHash updateHash();
	

}

abstract class AbstractSCCPasswordHash {

	byte[] hashMsg;
	PlaintextContainerInterface password;

	public AbstractSCCPasswordHash(PlaintextContainerInterface password, byte[] hashMsg) {
		this.password = password;
		this.hashMsg = hashMsg;
	}

	abstract byte[] toBytes();
	
	abstract String toString(Charset c);
	
	abstract boolean validatePasswordHash(PlaintextContainerInterface password);

}

abstract class AbstractSCCSignature {
	byte[] signatureMsg;
	PlaintextContainerInterface plaintext;
	AbstractSCCKeyPair keyPair;

	// keyPair, plaintext
	public AbstractSCCSignature(PlaintextContainerInterface plaintext, AbstractSCCKeyPair keyPair, byte[] signatureMasg) {
		this.plaintext = plaintext;
		this.keyPair = keyPair;
		this.signatureMsg = signatureMasg;
	}

	abstract byte[] toBytes();

	abstract String toString(Charset c);

	abstract boolean validateSignature();

	abstract SCCSignature updateSignature();

}

/*
 * abstract class AbstractSCCCiphertextOutputStream {
 * 
 * abstract ByteArrayOutputStream getStream();
 * 
 * abstract String getEncryptedContent();
 * 
 * abstract byte[] getEncryptedBytes();
 * 
 * }
 * 
 * abstract class AbstractPlaintextOutputStream {
 * 
 * }
 */
