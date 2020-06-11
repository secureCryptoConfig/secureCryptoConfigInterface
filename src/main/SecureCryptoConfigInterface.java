package main;

import java.security.Key;
import java.util.HashMap;

import javax.crypto.spec.SecretKeySpec;

abstract interface SecureCryptoConfigInterface {
	// Symmetric Encryption

	public AbstractSCCCiphertext symmetricEncrypt(AbstractSCCKey key, PlaintextContainerInterface plaintext);

	public AbstractSCCCiphertext symmetricReEncrypt(AbstractSCCKey key, AbstractSCCCiphertext ciphertext);

	public PlaintextContainerInterface symmetricDecrypt(AbstractSCCKey key, AbstractSCCCiphertext sccciphertext);

	//for file encryption?
	/**
	public AbstractSCCCiphertextStream streamEncrypt(AbstractSCCKey key, AbstractPlaintextContainerStream<?> plaintext);

	public AbstractSCCCiphertextStream streamReEncrypt(AbstractSCCKey key, AbstractSCCCiphertextStream ciphertext);

	public AbstractPlaintextContainerStream<?> streamDecrypt(AbstractSCCKey key, AbstractSCCCiphertextStream ciphertext);
	**/
	
	public AbstractSCCCiphertext streamEncrypt(AbstractSCCKey key, String filepath);

	public AbstractSCCCiphertext streamReEncrypt(AbstractSCCKey key, String filepath);

	public PlaintextContainerInterface streamDecrypt(AbstractSCCKey key, AbstractSCCCiphertext ciphertext, String filepath );
	
	
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

	public AbstractSCCSignature sign(AbstractSCCKeyPair keyPair, PlaintextContainerInterface plaintext);

	public AbstractSCCSignature reSign(AbstractSCCKeyPair keyPair, PlaintextContainerInterface plaintext);

	public boolean validateSignature(AbstractSCCKeyPair keyPair, AbstractSCCSignature signature);

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

/**
abstract interface AbstractPlaintextContainerStream<T> {
	public Stream<T> getPlaintextStream();
}

abstract class AbstractSCCCiphertextStream implements Stream<SCCCiphertext>{

}
**/

abstract class AbstractSCCAlgorithmParameters {
	int tagLength;
	byte[] nonce;
	String algo;
	AbstractSCCKey key;
	AbstractSCCKeyPair keyPair;
	PlaintextContainerInterface plain;
	
    protected AbstractSCCAlgorithmParameters(AbstractSCCKey key, byte[] nonce, int tag, String algo ) {
		this.key = key;
		this.nonce = nonce;
		this.tagLength = tag;
		this.algo = algo;
	}
    
    protected AbstractSCCAlgorithmParameters(AbstractSCCKeyPair keyPair, String algo ) {
		this.keyPair = keyPair;
		this.algo = algo;
	}
    
    protected AbstractSCCAlgorithmParameters(AbstractSCCKeyPair keyPair, String algo, PlaintextContainerInterface plain) {
		this.keyPair = keyPair;
		this.algo = algo;
		this.plain = plain;
	}
    
    //?
    HashMap<String, String> params = new HashMap<>();
    protected AbstractSCCAlgorithmParameters(HashMap<String, String> params)
    {
    	this.params = params;
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
	
	//enum SCCKeyType {
	//	Symmetric, Asymmetric
	//}

	//as static method in class
	//abstract AbstractSCCKey createKey(byte[] bytes);

	abstract String getDefaultAlgorithm();

}

abstract class AbstractSCCKeyPair{
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
}

abstract class AbstractSCCPasswordHash {

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
