package main;

import java.util.stream.Stream;

import javax.crypto.spec.SecretKeySpec;

import COSE.CoseException;

abstract interface SecureCryptoConfigInterface {
	//Symmetric Encryption
	public SCCCiphertext symmetricEncrypt(SCCKey key, PlaintextContainer plaintext) throws CoseException;

	public SCCCiphertext symmetricReEncrypt(SCCKey key, SCCCiphertext ciphertext);

	public PlaintextContainer symmetricDecrypt(SCCKey key, SCCCiphertext sccciphertext);

	public SCCCiphertextStream<?> streamEncrypt(SCCKey key, PlaintextContainerStream<?> plaintext);

	public SCCCiphertextStream<?> streamReEncrypt(SCCKey key, SCCCiphertextStream<?> ciphertext);

	public PlaintextContainerStream<?> streamDecrypt(SCCKey key, SCCCiphertextStream<?> ciphertext);
	
	//Asymmetric

	public SCCCiphertext[] encrypt(SCCKey[] key, PlaintextContainer plaintext);

	public SCCCiphertext asymmetricEncrypt(SCCKey key, PlaintextContainer plaintext);

	public SCCCiphertext AsymmetricReEncrypt(SCCKey key, SCCCiphertext ciphertext);

	public PlaintextContainer asymmetricDecrypt(SCCKey key, SCCCiphertext ciphertext);
	
	//Hashing

	public SCCHash hash(PlaintextContainer plaintext);

	public SCCHash reHash(PlaintextContainer plaintext);

	// How to verify Hash?
	public boolean verifyHash(PlaintextContainer plaintext, SCCHash hash);
	
	//Digital Signature

	public SCCSignature sign(SCCKey privateKey, PlaintextContainer plaintext);

	public SCCSignature reSign(SCCKey privateKey, PlaintextContainer plaintext);

	public boolean validteSignature(SCCKey publicKeyy, SCCSignature signature);
	
	//Password Hashing

	public SCCPasswordHash passwordHash(String password);

	public boolean verifyPassword(String password, SCCPasswordHash passwordhash);

	// TODO methods for key generation? Returning of SCCKey?
	public SCCKey generateKey();

}

abstract interface PlaintextContainer {

	public byte[] getPlaintext();

	boolean verifyHash(SCCHash scchash);
}

abstract interface PlaintextContainerStream<T> {
	public Stream<T> getPlaintextStream();
}

abstract class SCCCiphertextStream<T> implements Stream<T> {

}

abstract class SCCCiphertext {

	abstract SCCCiphertext sCCCiphertext(String ciphertext, SCCAlgorithmParameters parameters);

	abstract AlgorithmIdentifier getAlgorithmIdentifier(SCCCiphertext sccciphertext);

}

abstract class SCCAlgorithmParameters {

}

abstract class AlgorithmIdentifier {
	// named defined in IANA registry
	enum AlgorithmID {
		AEAD_AES_256_GCM, AEAD_AES_512_GCM, SHA3_512,
	}
}

//extends SecretKeySpec?
abstract class SCCKey extends SecretKeySpec {

	private SCCKey(byte[] key, String algorithm) {
		super(key, algorithm);
		// TODO Auto-generated constructor stub
	}

	enum SCCKeyType {
		Symmetric, Asymmetric
	}

	abstract SCCKey createKey(byte[] bytes);

	abstract SCCKeyType getSCCKeyType();

	abstract String getDefaultAlgorithm();

}

abstract class SCCHash {
	//abstract boolean verify(PlaintextContainer plaintext);
}

abstract class SCCPasswordHash {

}

abstract class SCCSignature {

}
