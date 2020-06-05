package main;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;

public class SecureCryptoConfig implements SecureCryptoConfigInterface {

	// TODO refactor in separate class?
	static enum AlgorithmIDEnum {
		AEAD_AES_256_GCM, AEAD_AES_512_GCM, SHA3_512,
	}

	public static HashSet<String> getEnums() {

		HashSet<String> values = new HashSet<String>();

		for (AlgorithmIDEnum c : AlgorithmIDEnum.values()) {
			values.add(c.name());
		}

		return values;
	}

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
		// SCCCiphertext sccciphertext = SCCCiphertext.getSCCCiphertext();
		// return sccciphertext;

		String sccalgorithmID = "AEAD_AES_256_GCM";

		// TODO mapping from sting to enum:

		if (getEnums().contains(sccalgorithmID)) {

			AlgorithmIDEnum chosenAlgorithmID = AlgorithmIDEnum.valueOf(sccalgorithmID);
			Cipher cipher;
			int nonceLength;
			int tagLength;
			String algo;
			final byte[] nonce;
			switch (chosenAlgorithmID) {
			case AEAD_AES_256_GCM:
				try {
					nonceLength = 32;
					tagLength = 128;
					algo = "AES/GCM/NoPadding";
					// ENCRYPTION
					cipher = Cipher.getInstance(algo);

					// GENERATE random nonce (number used once)
					nonce = UseCases.generateNonce(nonceLength);

					GCMParameterSpec spec = new GCMParameterSpec(tagLength, nonce);

					cipher.init(Cipher.ENCRYPT_MODE, key, spec);

					byte[] byteCipher = cipher.doFinal(plaintext.getPlaintext());
					SCCAlgorithmParameters param = new SCCAlgorithmParameters(key, nonce, tagLength, algo);
					SCCCiphertext c = new SCCCiphertext(byteCipher, param);
					return c;
				} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
						| InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
					return null;
				}
			default:

				return null;

			}
		}
		return null;
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

}
