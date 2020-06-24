package main;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;

import com.upokecenter.cbor.CBORObject;

import COSE.CoseException;
import COSE.HashMessage;
import COSE.OneKey;
import COSE.PasswordHashMessage;
import COSE.Sign1Message;

abstract interface SecureCryptoConfigInterface {
	
	// Symmetric Encryption
	public AbstractSCCCiphertext symmetricEncrypt(AbstractSCCKey key, PlaintextContainerInterface plaintext)
			throws CoseException;

	public AbstractSCCCiphertext symmetricReEncrypt(AbstractSCCKey key, AbstractSCCCiphertext ciphertext)
			throws CoseException;

	public PlaintextContainerInterface symmetricDecrypt(AbstractSCCKey key, AbstractSCCCiphertext sccciphertext)
			throws CoseException;
	

	// File encryption working with Streams
	public AbstractSCCCiphertextOutputStream streamEncrypt(AbstractSCCKey key, OutputStream outputStream) throws NoSuchAlgorithmException;

	public AbstractPlaintextOutputStream streamDecrypt(AbstractSCCKey key, AbstractSCCCiphertextOutputStream outputStream, InputStream inputStream);

	// Simple File encryption 
	public AbstractSCCCiphertext fileEncrypt(AbstractSCCKey key, String filepath) throws NoSuchAlgorithmException;

	public PlaintextContainerInterface fileDecrypt(AbstractSCCKey key, AbstractSCCCiphertext ciphertext,
			String filepath);

	
	// Asymmetric
	public AbstractSCCCiphertext asymmetricEncrypt(AbstractSCCKeyPair keyPair, PlaintextContainerInterface plaintext)
			throws CoseException;

	public AbstractSCCCiphertext asymmetricReEncrypt(AbstractSCCKeyPair keyPair, AbstractSCCCiphertext ciphertext)
			throws CoseException;

	public PlaintextContainerInterface asymmetricDecrypt(AbstractSCCKeyPair keyPair, AbstractSCCCiphertext ciphertext)
			throws CoseException;

	
	// Hashing
	public AbstractSCCHash hash(PlaintextContainerInterface plaintext) throws CoseException;

	public AbstractSCCHash reHash(PlaintextContainerInterface plaintext) throws CoseException;

	public boolean verifyHash(PlaintextContainerInterface plaintext, AbstractSCCHash hash) throws CoseException;

	
	// Digital Signature
	public AbstractSCCSignature sign(OneKey key, PlaintextContainerInterface plaintext) throws CoseException;

	public AbstractSCCSignature reSign(OneKey key, PlaintextContainerInterface plaintext) throws CoseException;

	public boolean validateSignature(OneKey key, AbstractSCCSignature signature);

	// Password Hashing
	public AbstractSCCPasswordHash passwordHash(PlaintextContainerInterface password) throws CoseException;

	public boolean verifyPassword(PlaintextContainerInterface password, AbstractSCCPasswordHash passwordhash)
			throws CoseException;


}

abstract interface PlaintextContainerInterface {

	abstract byte[] getByteArray();
	abstract String getString();
	
	abstract boolean verifyHash(SCCHash hash);

}


//currently only needed for file en/decryption (no COSE support)
abstract class AbstractSCCAlgorithmParameters {
	byte[] nonce;
	String algo;
	int tagLength;

	protected AbstractSCCAlgorithmParameters(byte[] nonce, int tag, String algo) {
		this.nonce = nonce;
		this.tagLength = tag;
		this.algo = algo;
	}

}

abstract class AbstractSCCCiphertext {
	
	AbstractSCCAlgorithmParameters parameters;
	byte[] ciphertext;
	byte[] msg;

	//only for file encryption (no COSE support)
	public AbstractSCCCiphertext(byte[] ciphertext, AbstractSCCAlgorithmParameters parameters) {
		this.ciphertext = ciphertext;
		this.parameters = parameters;
	}

	public AbstractSCCCiphertext(byte[] msg) {
		this.msg = msg;
	}

	abstract byte[] getMessageBytes();
	abstract CBORObject getAlgorithmIdentifier();
	
	abstract String getPlain();
	abstract PlaintextContainer getAsymmetricCipher();
	abstract PlaintextContainer getSymmetricCipher();

	abstract PlaintextContainer symmetricDecrypt(SCCKey key);
	abstract PlaintextContainer asymmetricDecrypt(SCCKeyPair keyPair);
	

}

abstract class AbstractSCCKey {

	SecretKey key;
	String algorithm;

	protected AbstractSCCKey(SecretKey key, String algorithm) {
		this.key = key;
		this.algorithm = algorithm;
	}

	abstract String getAlgorithm();
	abstract SecretKey getSecretKey();


}

abstract class AbstractSCCKeyPair {
	KeyPair pair;
	String algorithm;

	protected AbstractSCCKeyPair(KeyPair pair, String algorithm) {
		this.algorithm = algorithm;
		this.pair = pair;
	}
	
	abstract String getAlgorithm();
	abstract KeyPair getKeyPair();
	abstract PrivateKey getPrivate();
	abstract PublicKey getPublic();

}

abstract class AbstractSCCHash {
	
	abstract boolean verifyHash(PlaintextContainer plain);

	abstract byte[] getMessageBytes();
	abstract HashMessage convertByteToMsg();
	abstract CBORObject getAlgorithmIdentifier();
	
	abstract String getPlain();
	abstract PlaintextContainer getHashedContent();

}

abstract class AbstractSCCPasswordHash {
	abstract boolean verifyHash(PlaintextContainer password);

	abstract byte[] getMessageBytes();
	abstract PasswordHashMessage convertByteToMsg();
	abstract CBORObject getAlgorithmIdentifier();
	
	abstract String getPlain();
	abstract PlaintextContainer getHashedContent();

}

abstract class AbstractSCCSignature {
	byte[] signatureMsg;

	public AbstractSCCSignature(byte[] signatureMsg) {
		this.signatureMsg = signatureMsg;
	}

	abstract byte[] getMessageBytes();
	abstract Sign1Message convertByteToMsg();
	abstract CBORObject getAlgorithmIdentifier();
	
	abstract boolean validateSignature(OneKey key);
	
	abstract String getPlain();
	abstract PlaintextContainer getSignature();

}

abstract class AbstractSCCCiphertextOutputStream extends CipherOutputStream{
	SCCAlgorithmParameters param;
	Cipher c;
	public AbstractSCCCiphertextOutputStream(OutputStream os, Cipher c, SCCAlgorithmParameters param) {
		super(os, c);
		this.param = param;
		this.c = c;
	}

}

abstract class AbstractPlaintextOutputStream extends CipherInputStream{

	public AbstractPlaintextOutputStream(InputStream is, Cipher c) {
		super(is, c);
	}

}

