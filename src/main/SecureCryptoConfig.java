package main;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class SecureCryptoConfig implements SecureCryptoConfigInterface {

	// Only draft
	@Override
	public SCCCiphertext symmetricEncrypt(AbstractSCCKey key, PlaintextContainerInterface plaintext) {

		// ArrayList<String> algorithms = new ArrayList<String>();

		// read our Algorithms for symmetric encryption out of JSON
		// algorithms = JSONReader.getAlgos(CryptoUseCase.SymmetricEncryption);

		// get first one, later look what to do if first is not validate -> take next
		// String alg = algorithms.get(0);
		// return new SCCCiphertext

		// return doSymmetricEncryption(key, plaintext, alg);
		SCCCiphertext sccciphertext = SCCCiphertext.getSCCCiphertext();
		return sccciphertext;

	}

	private String doSymmetricEncryption(SecretKey key, String plainText, String alg) {
		// Split Algo Identifier in its parameters
		String[] parameters = alg.split("_");
		String algorithm = parameters[0];
		String mode = parameters[1];
		int keyLength = Integer.parseInt(parameters[2]);
		int tagLenth = Integer.parseInt(parameters[3]);
		int nonceLength = Integer.parseInt(parameters[4]);

		try {

			// ENCRYPTION
			Cipher cipher = Cipher.getInstance(algorithm + "/" + mode + "/NoPadding");

			// GENERATE random nonce (number used once)
			final byte[] nonce = UseCases.generateNonce(nonceLength);

			GCMParameterSpec spec = new GCMParameterSpec(tagLenth, nonce);
			cipher.init(Cipher.ENCRYPT_MODE, key, spec);

			byte[] byteCipher = cipher.doFinal(UseCases.getByte(plainText));
			// CONVERSION of raw bytes to BASE64 representation
			String cipherText = Base64.getEncoder().encodeToString(byteCipher);
			return cipherText;

		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
				| InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
			return null;
		}

	}

	@Override
	public AbstractSCCCiphertext symmetricReEncrypt(AbstractSCCKey key, AbstractSCCCiphertext ciphertext) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public PlaintextContainer symmetricDecrypt(AbstractSCCKey key, AbstractSCCCiphertext sccciphertext) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public SCCCiphertextStream<?> streamEncrypt(AbstractSCCKey key, PlaintextContainerStream<?> plaintext) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public SCCCiphertextStream<?> streamReEncrypt(AbstractSCCKey key, SCCCiphertextStream<?> ciphertext) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public PlaintextContainerStream<?> streamDecrypt(AbstractSCCKey key, SCCCiphertextStream<?> ciphertext) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public AbstractSCCCiphertext[] encrypt(AbstractSCCKey[] key, PlaintextContainerInterface plaintext) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public AbstractSCCCiphertext asymmetricEncrypt(AbstractSCCKey key, PlaintextContainerInterface plaintext) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public AbstractSCCCiphertext AsymmetricReEncrypt(AbstractSCCKey key, AbstractSCCCiphertext ciphertext) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public PlaintextContainerInterface asymmetricDecrypt(AbstractSCCKey key, AbstractSCCCiphertext ciphertext) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public AbstractSCCHash hash(PlaintextContainerInterface plaintext) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public AbstractSCCHash reHash(PlaintextContainerInterface plaintext) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean verifyHash(PlaintextContainerInterface plaintext, AbstractSCCHash hash) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public AbstractSCCSignature sign(AbstractSCCKey privateKey, PlaintextContainerInterface plaintext) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public AbstractSCCSignature reSign(AbstractSCCKey privateKey, PlaintextContainerInterface plaintext) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean validteSignature(AbstractSCCKey publicKeyy, AbstractSCCSignature signature) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public AbstractSCCPasswordHash passwordHash(String password) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean verifyPassword(String password, AbstractSCCPasswordHash passwordhash) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public SCCKey generateKey() {
		// TODO Auto-generated method stub
		return null;
	}

}
