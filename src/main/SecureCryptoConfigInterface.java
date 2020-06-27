package main;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;

import com.upokecenter.cbor.CBORObject;

import COSE.AlgorithmID;
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
	public AbstractSCCCiphertextOutputStream streamEncrypt(AbstractSCCKey key, OutputStream outputStream)
			throws NoSuchAlgorithmException;

	public AbstractPlaintextOutputStream streamDecrypt(AbstractSCCKey key,
			AbstractSCCCiphertextOutputStream outputStream, InputStream inputStream);

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

	public AbstractSCCHash updateHash(PlaintextContainerInterface plaintext) throws CoseException;

	public boolean validateHash(PlaintextContainerInterface plaintext, AbstractSCCHash hash) throws CoseException;

	// Digital Signature
	public AbstractSCCSignature sign(AbstractSCCKeyPair key, PlaintextContainerInterface plaintext)
			throws CoseException;

	public AbstractSCCSignature updateSignature(AbstractSCCKeyPair key, PlaintextContainerInterface plaintext)
			throws CoseException;

	public boolean validateSignature(AbstractSCCKeyPair key, AbstractSCCSignature signature);

	// Password Hashing
	public AbstractSCCPasswordHash passwordHash(PlaintextContainerInterface password) throws CoseException;

	public boolean validatePasswordHash(PlaintextContainerInterface password, AbstractSCCPasswordHash passwordhash)
			throws CoseException;

}

abstract interface PlaintextContainerInterface {

	abstract byte[] getByteArray();

	abstract String getBase64();

	abstract String getString(Charset c);

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
	byte[] cipher;
	byte[] msg;
	PlaintextContainerInterface plain;
	AbstractSCCKey key;
	AbstractSCCKeyPair keyPair;

	// only for file encryption (no COSE support)
	public AbstractSCCCiphertext(byte[] cipher, AbstractSCCAlgorithmParameters parameters) {
		this.cipher = cipher;
		this.parameters = parameters;
	}

	public AbstractSCCCiphertext(PlaintextContainerInterface plain, byte[] cipher, AbstractSCCKey key, byte[] msg) {
		this.plain = plain;
		this.cipher = cipher;
		this.key = key;
		this.msg = msg;
	}
	
	public AbstractSCCCiphertext(PlaintextContainerInterface plain, byte[] cipher, AbstractSCCKeyPair keyPair, byte[] msg) {
		this.plain = plain;
		this.cipher = cipher;
		this.keyPair = keyPair;
		this.msg = msg;
	}

	abstract byte[] getMessageBytes();

	abstract AlgorithmID getAlgorithmIdentifier() throws CoseException;

	abstract PlaintextContainerInterface getPlain();

	abstract byte[] getCipherBytes();
	
	abstract PlaintextContainer asymmetricDecrypt(SCCKeyPair keyPair);
	abstract PlaintextContainer symmetricDecrypt(SCCKey key);

}

abstract class AbstractSCCKey {

	byte[] key;
	String algorithm;

	protected AbstractSCCKey(byte[] key, String algorithm) {
		this.key = key;
		this.algorithm = algorithm;

	}

	abstract SecretKey getSecretKey();

	abstract byte[] getByteArray();

	abstract String getAlgorithm();

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

	abstract boolean validateSignature(SCCKeyPair key);

	abstract String getPlain();

	abstract PlaintextContainer getSignature();

}

abstract class AbstractSCCCiphertextOutputStream extends CipherOutputStream {
	SCCAlgorithmParameters param;
	Cipher c;

	public AbstractSCCCiphertextOutputStream(OutputStream os, Cipher c, SCCAlgorithmParameters param) {
		super(os, c);
		this.param = param;
		this.c = c;
	}

}

abstract class AbstractPlaintextOutputStream extends CipherInputStream {

	public AbstractPlaintextOutputStream(InputStream is, Cipher c) {
		super(is, c);
	}

}
