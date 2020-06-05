package main;

import java.util.stream.Stream;

import javax.crypto.spec.SecretKeySpec;

abstract interface SecureCryptoConfigInterface {
	// Symmetric Encryption

	public AbstractSCCCiphertext symmetricEncrypt(AbstractSCCKey key, PlaintextContainerInterface plaintext);

	public AbstractSCCCiphertext symmetricReEncrypt(AbstractSCCKey key, AbstractSCCCiphertext ciphertext);

	public PlaintextContainerInterface symmetricDecrypt(AbstractSCCKey key, AbstractSCCCiphertext sccciphertext);

	public SCCCiphertextStream<?> streamEncrypt(AbstractSCCKey key, PlaintextContainerStream<?> plaintext);

	public SCCCiphertextStream<?> streamReEncrypt(AbstractSCCKey key, SCCCiphertextStream<?> ciphertext);

	public PlaintextContainerStream<?> streamDecrypt(AbstractSCCKey key, SCCCiphertextStream<?> ciphertext);

	public AbstractSCCCiphertext[] encrypt(AbstractSCCKey[] key, PlaintextContainerInterface plaintext);

	// Asymmetric
	
	public AbstractSCCCiphertext asymmetricEncrypt(AbstractSCCKey key, PlaintextContainerInterface plaintext);

	public AbstractSCCCiphertext AsymmetricReEncrypt(AbstractSCCKey key, AbstractSCCCiphertext ciphertext);

	public PlaintextContainerInterface asymmetricDecrypt(AbstractSCCKey key, AbstractSCCCiphertext ciphertext);

	// Hashing

	public AbstractSCCHash hash(PlaintextContainerInterface plaintext);

	public AbstractSCCHash reHash(PlaintextContainerInterface plaintext);

	// How to verify Hash?
	public boolean verifyHash(PlaintextContainerInterface plaintext, AbstractSCCHash hash);

	// Digital Signature

	public AbstractSCCSignature sign(AbstractSCCKey privateKey, PlaintextContainerInterface plaintext);

	public AbstractSCCSignature reSign(AbstractSCCKey privateKey, PlaintextContainerInterface plaintext);

	public boolean validteSignature(AbstractSCCKey publicKeyy, AbstractSCCSignature signature);

	// Password Hashing

	public AbstractSCCPasswordHash passwordHash(String password);

	public boolean verifyPassword(String password, AbstractSCCPasswordHash passwordhash);

	// TODO methods for key generation? Returning of SCCKey?
	

}

abstract interface PlaintextContainerInterface {

	abstract byte[] getByteArray();
	abstract String getPlain();
	boolean verifyHash(AbstractSCCHash scchash);
}

abstract interface PlaintextContainerStream<T> {
	public Stream<T> getPlaintextStream();
}

abstract class SCCCiphertextStream<T> implements Stream<T> {

}

abstract class AbstractSCCAlgorithmParameters {
	int tagLength;
	byte[] nonce;
	String algo;
	AbstractSCCKey key;
	
    protected AbstractSCCAlgorithmParameters(AbstractSCCKey key, byte[] nonce, int tag, String algo ) {
		this.key = key;
		this.nonce = nonce;
		this.tagLength = tag;
		this.algo = algo;
	}

}

abstract class AbstractSCCCiphertext {

	AbstractSCCAlgorithmParameters parameters;
	byte[] ciphertext;
	
	public AbstractSCCCiphertext(byte[] ciphertext, AbstractSCCAlgorithmParameters parameters) {
		this.ciphertext = ciphertext;
		this.parameters = parameters;
	}

	abstract AbstractAlgorithmIdentifier getAlgorithmIdentifier(AbstractSCCCiphertext sccciphertext);

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
abstract class AbstractSCCKey extends SecretKeySpec {

	private static final long serialVersionUID = -5728367200343756529L;

	protected AbstractSCCKey(byte[] key, String algorithm) {
		super(key, algorithm);

	}

	enum SCCKeyType {
		Symmetric, Asymmetric
	}

	abstract AbstractSCCKey createKey(byte[] bytes);

	abstract SCCKeyType getSCCKeyType();

	abstract String getDefaultAlgorithm();

}

abstract class AbstractSCCHash {
	abstract boolean verify(PlaintextContainer plaintext);
	
	@Override
	public abstract String toString();
}

abstract class AbstractSCCPasswordHash {

}

abstract class AbstractSCCSignature {

}
