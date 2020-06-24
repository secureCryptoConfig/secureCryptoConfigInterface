package main;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;

import COSE.CoseException;

import COSE.OneKey;

abstract interface SecureCryptoConfigInterface {
	// Symmetric Encryption

	public AbstractSCCCiphertext symmetricEncrypt(AbstractSCCKey key, PlaintextContainerInterface plaintext)
			throws CoseException;

	public AbstractSCCCiphertext symmetricReEncrypt(AbstractSCCKey key, AbstractSCCCiphertext ciphertext)
			throws CoseException;

	public PlaintextContainerInterface symmetricDecrypt(AbstractSCCKey key, AbstractSCCCiphertext sccciphertext)
			throws CoseException;
	
	public AbstractSCCCiphertext[] encrypt(AbstractSCCKey[] key, PlaintextContainerInterface plaintext);


	// for file encryption
	public AbstractSCCCiphertextOutputStream streamEncrypt(AbstractSCCKey key, OutputStream outputStream) throws NoSuchAlgorithmException;

	public AbstractSCCCiphertextOutputStream streamReEncrypt(AbstractSCCKey key, AbstractSCCCiphertextOutputStream ciphertext);

	public AbstractPlaintextOutputStream streamDecrypt(AbstractSCCKey key, AbstractSCCCiphertextOutputStream outputStream, InputStream inputStream);

	// simple File encryption
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

	// How to verify Hash?
	public boolean verifyHash(PlaintextContainerInterface plaintext, AbstractSCCHash hash) throws CoseException;

	// Digital Signature
	/**
	 * public AbstractSCCSignature sign(AbstractSCCKeyPair keyPair,
	 * PlaintextContainerInterface plaintext);
	 * 
	 * public AbstractSCCSignature reSign(AbstractSCCKeyPair keyPair,
	 * PlaintextContainerInterface plaintext);
	 * 
	 * public boolean validateSignature(AbstractSCCKeyPair keyPair,
	 * AbstractSCCSignature signature);
	 **/
	public AbstractSCCSignature sign(OneKey key, PlaintextContainerInterface plaintext) throws CoseException;

	// same as sign?
	public AbstractSCCSignature reSign(OneKey key, PlaintextContainerInterface plaintext) throws CoseException;

	public boolean validateSignature(OneKey key, AbstractSCCSignature signature);

	// Password Hashing

	public AbstractSCCPasswordHash passwordHash(PlaintextContainerInterface password) throws CoseException;

	public boolean verifyPassword(PlaintextContainerInterface password, AbstractSCCPasswordHash passwordhash)
			throws CoseException;

	// TODO methods for key generation? Returning of SCCKey?

}

abstract interface PlaintextContainerInterface {

	abstract byte[] getByteArray();

	abstract String getPlain();

	boolean verifyHash(AbstractSCCHash scchash);
}

/**
 * abstract interface AbstractPlaintextContainerStream<T> { public Stream<T>
 * getPlaintextStream(); }
 * 
 * abstract class AbstractSCCCiphertextStream implements Stream<SCCCiphertext>{
 * 
 * }
 **/

abstract class AbstractSCCAlgorithmParameters {
	byte[] nonce;
	String algo;
	PlaintextContainerInterface plain;
	byte[] salt;
	int keysize, iterations, tagLength;
	OneKey k;

	protected AbstractSCCAlgorithmParameters(OneKey k) {
		this.k = k;
	}

	protected AbstractSCCAlgorithmParameters(byte[] nonce, int tag, String algo) {
		this.nonce = nonce;
		this.tagLength = tag;
		this.algo = algo;
	}

	protected AbstractSCCAlgorithmParameters(String algo) {
		this.algo = algo;
	}

	protected AbstractSCCAlgorithmParameters(String algo, PlaintextContainerInterface plain) {
		this.algo = algo;
		this.plain = plain;
	}

	protected AbstractSCCAlgorithmParameters(String algo, byte[] salt, int keysize, int iterations) {
		this.algo = algo;
		this.salt = salt;
		this.keysize = keysize;
		this.iterations = iterations;
	}

}

abstract class AbstractSCCCiphertext {

	AbstractSCCAlgorithmParameters parameters;
	byte[] ciphertext;
	byte[] msg;

	public AbstractSCCCiphertext(byte[] ciphertext, AbstractSCCAlgorithmParameters parameters) {
		this.ciphertext = ciphertext;
		this.parameters = parameters;
	}

	public AbstractSCCCiphertext(byte[] msg) {
		this.msg = msg;
	}

	abstract String getCiphertext();

	abstract byte[] getCipherBytes();
	// abstract CBORObject getAlgorithmIdentifier();

	@Override
	public abstract String toString();

}

abstract class AbstractSCCKey {

	SecretKey key;
	String algorithm;

	protected AbstractSCCKey(SecretKey key, String algorithm) {
		this.key = key;
		this.algorithm = algorithm;
	}

	abstract String getAlgorithm();

	abstract SecretKey getKey();

	// as static method in class
	// abstract AbstractSCCKey createKey(byte[] bytes);

}

abstract class AbstractSCCKeyPair {
	KeyPair pair;
	String algorithm;

	protected AbstractSCCKeyPair(KeyPair pair, String algorithm) {
		this.algorithm = algorithm;
		this.pair = pair;
	}

}

abstract class AbstractSCCHash {
	abstract boolean verify(PlaintextContainer plaintext);

	@Override
	public abstract String toString();

	abstract String getAlgo();

	abstract byte[] getByteArray();

}

abstract class AbstractSCCPasswordHash {
	abstract boolean verify(PlaintextContainer plaintext);

	@Override
	public abstract String toString();

	abstract byte[] getByteArray();

}

abstract class AbstractSCCSignature {
	byte[] signatureMsg;

	public AbstractSCCSignature(byte[] signatureMsg) {
		this.signatureMsg = signatureMsg;
	}

	@Override
	public abstract String toString();

	abstract byte[] getSignatureMsg();

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


/**
 * abstract class AbstractAlgorithmIdentifier { // named defined in IANA
 * registry enum AlgorithmID { AEAD_AES_256_GCM, AEAD_AES_512_GCM, SHA3_512, } }
 **/
