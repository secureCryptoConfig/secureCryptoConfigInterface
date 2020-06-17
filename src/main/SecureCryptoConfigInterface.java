package main;

import java.security.Key;

import javax.crypto.SecretKey;


import COSE.CoseException;
import COSE.OneKey;

abstract interface SecureCryptoConfigInterface {
	// Symmetric Encryption

	public AbstractSCCCiphertext symmetricEncrypt(AbstractSCCKey key, PlaintextContainerInterface plaintext) throws CoseException;

	public AbstractSCCCiphertext symmetricReEncrypt(AbstractSCCKey key, AbstractSCCCiphertext ciphertext) throws CoseException;

	public PlaintextContainerInterface symmetricDecrypt(AbstractSCCKey key, AbstractSCCCiphertext sccciphertext);

	// for file encryption?
	/**
	 * public AbstractSCCCiphertextStream streamEncrypt(AbstractSCCKey key,
	 * AbstractPlaintextContainerStream<?> plaintext);
	 * 
	 * public AbstractSCCCiphertextStream streamReEncrypt(AbstractSCCKey key,
	 * AbstractSCCCiphertextStream ciphertext);
	 * 
	 * public AbstractPlaintextContainerStream<?> streamDecrypt(AbstractSCCKey key,
	 * AbstractSCCCiphertextStream ciphertext);
	 **/

	public AbstractSCCCiphertext streamEncrypt(AbstractSCCKey key, String filepath);

	public AbstractSCCCiphertext streamReEncrypt(AbstractSCCKey key, String filepath);

	public PlaintextContainerInterface streamDecrypt(AbstractSCCKey key, AbstractSCCCiphertext ciphertext,
			String filepath);

	public AbstractSCCCiphertext[] encrypt(AbstractSCCKey[] key, PlaintextContainerInterface plaintext);

	// Asymmetric

	public AbstractSCCCiphertext asymmetricEncrypt(AbstractSCCKeyPair keyPair, PlaintextContainerInterface plaintext);

	public AbstractSCCCiphertext asymmetricReEncrypt(AbstractSCCKeyPair keyPair, AbstractSCCCiphertext ciphertext);

	public PlaintextContainerInterface asymmetricDecrypt(AbstractSCCKeyPair keyPair, AbstractSCCCiphertext ciphertext);

	// Hashing

	public AbstractSCCHash hash(PlaintextContainerInterface plaintext);

	public AbstractSCCHash reHash(PlaintextContainerInterface plaintext);

	// How to verify Hash?
	public boolean verifyHash(PlaintextContainerInterface plaintext, AbstractSCCHash hash);

	// Digital Signature
	/**
	public AbstractSCCSignature sign(AbstractSCCKeyPair keyPair, PlaintextContainerInterface plaintext);

	public AbstractSCCSignature reSign(AbstractSCCKeyPair keyPair, PlaintextContainerInterface plaintext);

	public boolean validateSignature(AbstractSCCKeyPair keyPair, AbstractSCCSignature signature);
	**/
	public AbstractSCCSignature sign(OneKey key, PlaintextContainerInterface plaintext) throws CoseException;

	//same as sign?
	public AbstractSCCSignature reSign(OneKey key, PlaintextContainerInterface plaintext) throws CoseException;

	public boolean validateSignature(OneKey key, AbstractSCCSignature signature);

	// Password Hashing

	public AbstractSCCPasswordHash passwordHash(PlaintextContainerInterface password);

	public boolean verifyPassword(PlaintextContainerInterface password, AbstractSCCPasswordHash passwordhash);

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
	//abstract CBORObject getAlgorithmIdentifier();

	@Override
	public abstract String toString();

}

abstract class AbstractAlgorithmIdentifier {
	// named defined in IANA registry
	enum AlgorithmID {
		AEAD_AES_256_GCM, AEAD_AES_512_GCM, SHA3_512,
	}
}

//extends SecretKeySpec?
abstract class AbstractSCCKey {

	SecretKey key;
	String algorithm;

	protected AbstractSCCKey(SecretKey key, String algorithm) {
		this.key = key;
		this.algorithm = algorithm;
	}

	abstract String getAlgorithm();

	abstract SecretKey getKey();

	// enum SCCKeyType {
	// Symmetric, Asymmetric
	// }

	// as static method in class
	// abstract AbstractSCCKey createKey(byte[] bytes);

}

abstract class AbstractSCCKeyPair {
	Key publicKey, privateKey;
	String algorithm;

	protected AbstractSCCKeyPair(Key publicKey, Key privateKey, String algorithm) {
		this.algorithm = algorithm;
		this.publicKey = publicKey;
		this.privateKey = privateKey;
	}

}

abstract class AbstractSCCHash {
	abstract boolean verify(PlaintextContainer plaintext);

	@Override
	public abstract String toString();
	abstract String getAlgo();
}

abstract class AbstractSCCPasswordHash {
	abstract boolean verify(PlaintextContainer plaintext);

	@Override
	public abstract String toString();

	abstract String getAlgo();
	abstract byte[] getSalt();
	abstract int getKeySize();
	abstract int getIterations();
	


}

abstract class AbstractSCCSignature {
	AbstractSCCAlgorithmParameters parameters;
	byte[] signature;

	public AbstractSCCSignature(byte[] signature, AbstractSCCAlgorithmParameters parameters) {
		this.signature = signature;
		this.parameters = parameters;
	}

	@Override
	public abstract String toString();

}
