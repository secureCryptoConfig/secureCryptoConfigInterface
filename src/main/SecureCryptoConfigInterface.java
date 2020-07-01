package main;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.SecretKey;

import COSE.AlgorithmID;
import COSE.CoseException;
import COSE.HashMessage;
import COSE.Message;
import COSE.PasswordHashMessage;
import COSE.Sign1Message;
import main.SCCKey.SCCKeyAlgorithm;

abstract interface SecureCryptoConfigInterface {

	// Symmetric Encryption
	public AbstractSCCCiphertext symmetricEncrypt(AbstractSCCKey key, PlaintextContainerInterface plaintext)
			throws CoseException;
	
	public AbstractSCCCiphertext symmetricEncrypt(AbstractSCCKey key, byte[] plaintext)
			throws CoseException;
	
	public AbstractSCCCiphertext symmetricReEncrypt(AbstractSCCKey key, AbstractSCCCiphertext ciphertext)
			throws CoseException;

	public PlaintextContainerInterface symmetricDecrypt(AbstractSCCKey key, AbstractSCCCiphertext sccciphertext)
			throws CoseException;

	// File encryption working with Streams
	public AbstractSCCCiphertextOutputStream streamEncrypt(AbstractSCCKey key, InputStream inputStream)
			throws NoSuchAlgorithmException;

	// public AbstractPlaintextOutputStream streamDecrypt(AbstractSCCKey key,
	// AbstractSCCCiphertextOutputStream outputStream, InputStream inputStream);

	// Simple File encryption
	public AbstractSCCCiphertext fileEncrypt(AbstractSCCKey key, String filepath) throws NoSuchAlgorithmException;

	public PlaintextContainerInterface fileDecrypt(AbstractSCCKey key, AbstractSCCCiphertext ciphertext,
			String filepath);

	// Asymmetric
	public AbstractSCCCiphertext asymmetricEncrypt(AbstractSCCKeyPair keyPair, PlaintextContainerInterface plaintext)
			throws CoseException;
	
	public AbstractSCCCiphertext asymmetricEncrypt(AbstractSCCKeyPair keyPair, byte[] plaintext)
			throws CoseException;

	public AbstractSCCCiphertext asymmetricReEncrypt(AbstractSCCKeyPair keyPair, AbstractSCCCiphertext ciphertext)
			throws CoseException;

	public PlaintextContainerInterface asymmetricDecrypt(AbstractSCCKeyPair keyPair, AbstractSCCCiphertext ciphertext)
			throws CoseException;

	// Hashing
	public AbstractSCCHash hash(PlaintextContainerInterface plaintext) throws CoseException;

	public AbstractSCCHash hash(byte[] plaintext) throws CoseException;

	public AbstractSCCHash updateHash(AbstractSCCHash hash) throws CoseException;

	public boolean validateHash(PlaintextContainerInterface plaintext, AbstractSCCHash hash) throws CoseException;

	// Digital Signature
	public AbstractSCCSignature sign(AbstractSCCKeyPair key, PlaintextContainerInterface plaintext)
			throws CoseException;
	
	public AbstractSCCSignature sign(AbstractSCCKeyPair key, byte[] plaintext)
			throws CoseException;

	public AbstractSCCSignature updateSignature(AbstractSCCKeyPair key, AbstractSCCSignature signature)
			throws CoseException;

	public boolean validateSignature(AbstractSCCKeyPair key, AbstractSCCSignature signature);

	// Password Hashing
	public AbstractSCCPasswordHash passwordHash(PlaintextContainerInterface password) throws CoseException;

	public AbstractSCCPasswordHash passwordHash(byte[] password) throws CoseException;

	public boolean validatePasswordHash(PlaintextContainerInterface password, AbstractSCCPasswordHash passwordhash)
			throws CoseException;

}

abstract interface PlaintextContainerInterface {

	abstract byte[] getPlaintextBytes();

	abstract String getPlaintextAsString(Charset c);

	abstract boolean validateHash(AbstractSCCHash hash);
	
	abstract boolean validatePasswordHash(AbstractSCCPasswordHash passwordHash);
	
	abstract SCCCiphertext symmetricEncrypt(AbstractSCCKey key);
	
	abstract SCCCiphertext asymmetricEncrypt(AbstractSCCKeyPair pair);
	
	abstract SCCSignature sign(AbstractSCCKeyPair keyPair);
	
	abstract SCCHash hash();
	
	abstract SCCPasswordHash passwordHash();
	
}


abstract class AbstractSCCCiphertext {
	
	byte[] ciphertext;
	byte[] msg;

	public AbstractSCCCiphertext(byte[] ciphertext, byte[] msg) {
		this.ciphertext = ciphertext;
		this.msg = msg;
	}


	abstract byte[] getMessageBytes();

	abstract Message convertByteToMsg();

	abstract AlgorithmID getAlgorithmIdentifier();
	
	abstract byte[] getCiphertextBytes();
	
	abstract String getCiphertextAsString(Charset c);

	abstract PlaintextContainer asymmetricDecrypt(AbstractSCCKeyPair keyPair);

	abstract PlaintextContainer symmetricDecrypt(AbstractSCCKey key);
	
	abstract SCCCiphertext symmetricReEncrypt(AbstractSCCKey key);
	
	abstract SCCCiphertext asymmetricReEncrypt(AbstractSCCKeyPair keyPair);

}

abstract class AbstractSCCKey {

	byte[] key;
	SCCKeyAlgorithm algorithm;

	protected AbstractSCCKey(byte[] key, SCCKeyAlgorithm algorithm) {
		this.key = key;
		this.algorithm = algorithm;

	}

	abstract SecretKey getSecretKey();

	abstract byte[] getByteArray();

	abstract String getAlgorithm();

}

abstract class AbstractSCCKeyPair {
	KeyPair pair;

	protected AbstractSCCKeyPair(KeyPair pair) {
		this.pair = pair;
	}

	abstract KeyPair getKeyPair();

	abstract PrivateKey getPrivate();

	abstract PublicKey getPublic();

}

abstract class AbstractSCCHash {
	
	byte[] hashMsg;
	PlaintextContainerInterface plaintext, hash;
	
	public AbstractSCCHash(PlaintextContainerInterface plaintext, PlaintextContainerInterface hash, byte[] hashMsg)
	{
		this.hashMsg = hashMsg;
		this.hash = hash;
		this.plaintext = plaintext;
	}

	abstract boolean validateHash(PlaintextContainerInterface plaintext);

	abstract SCCHash updateHash();
	
	abstract byte[] getMessageBytes();

	abstract HashMessage convertByteToMsg();

	abstract AlgorithmID getAlgorithmIdentifier();

	abstract PlaintextContainerInterface getPlaintextAsPlaintextContainer();

	abstract String getPlaintextAsString(Charset c);

	abstract PlaintextContainerInterface getHashAsPlaintextContainer();
	
	abstract String getHashAsString(Charset c);
	
	abstract byte[] getHashBytes();

}

abstract class AbstractSCCPasswordHash {
	
	byte[] hashMsg;
	PlaintextContainerInterface plaintext, hash;
	SecureCryptoConfig scc = new SecureCryptoConfig();
	
	public AbstractSCCPasswordHash(PlaintextContainerInterface password, PlaintextContainerInterface hash, byte[] hashMsg) {
		this.hashMsg = hashMsg;
		this.hash = hash;
		this.plaintext = password;
	}
	
	abstract boolean validatePasswordHash(PlaintextContainerInterface password);

	abstract byte[] getMessageBytes();

	abstract PasswordHashMessage convertByteToMsg();

	abstract AlgorithmID getAlgorithmIdentifier();

	abstract PlaintextContainerInterface getPlaintextAsPlaintextContainer();

	abstract String getPlaintextAsString(Charset c);

	abstract PlaintextContainerInterface getHashAsPlaintextContainer();
	
	abstract String getHashAsString(Charset c);
	
	abstract byte[] getHashBytes();

}

abstract class AbstractSCCSignature {
	byte[] signatureMsg;
	PlaintextContainerInterface plaintext, signature;

	public AbstractSCCSignature(PlaintextContainer plaintext, PlaintextContainer signature, byte[] signatureMsg) {
		this.signatureMsg = signatureMsg;
		this.plaintext = plaintext;
		this.signature = signature;
	}

	abstract byte[] getMessageBytes();

	abstract Sign1Message convertByteToMsg();

	abstract AlgorithmID getAlgorithmIdentifier();

	abstract boolean validateSignature(AbstractSCCKeyPair pair);

	abstract PlaintextContainerInterface getPlaintextAsPlaintextContainer();

	abstract String getPlaintextAsString(Charset c);

	abstract PlaintextContainer getSignatureAsPlaintextContainer();
	
	abstract String getSignatureAsString(Charset c);
	
	abstract byte[] getSignatureBytes();
	
	abstract SCCSignature updateSignature (AbstractSCCKeyPair pair, SecureCryptoConfig scc);

}

abstract class AbstractSCCCiphertextOutputStream {
	
	abstract ByteArrayOutputStream getStream();

	abstract String getEncryptedContent();

	abstract byte[] getEncryptedBytes();

}

abstract class AbstractPlaintextOutputStream {

}
