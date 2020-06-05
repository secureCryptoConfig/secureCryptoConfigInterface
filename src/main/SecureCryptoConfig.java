package main;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;

import main.JSONReader.CryptoUseCase;

public class SecureCryptoConfig implements SecureCryptoConfigInterface {

	// TODO refactor in separate class?
	static enum AlgorithmIDEnum {
		AES_GCM_256_128_128, AES_GCM_256_256_128, SHA3_512,
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

		ArrayList<String> algorithms = new ArrayList<String>();

		// read our Algorithms for symmetric encryption out of JSON
		algorithms = JSONReader.getAlgos(CryptoUseCase.SymmetricEncryption);

		// get first one, later look what to do if first is not validate -> take next
		String alg = algorithms.get(0);
		// return new SCCCiphertext

		// return doSymmetricEncryption(key, plaintext, alg);
		// SCCCiphertext sccciphertext = SCCCiphertext.getSCCCiphertext();
		// return sccciphertext;

		String sccalgorithmID = "AES_GCM_256_128_128";

		// TODO mapping from sting to enum:

		if (getEnums().contains(sccalgorithmID)) {

			AlgorithmIDEnum chosenAlgorithmID = AlgorithmIDEnum.valueOf(sccalgorithmID);
			Cipher cipher;
			int nonceLength;
			int tagLength;
			String algo;
			final byte[] nonce;
			switch (chosenAlgorithmID) {
			case AES_GCM_256_128_128:
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

					byte[] byteCipher = cipher.doFinal(plaintext.getByteArray());
					SCCAlgorithmParameters param = new SCCAlgorithmParameters(key, nonce, tagLength, algo);
					SCCCiphertext c = new SCCCiphertext(byteCipher, param);
					return c;
				} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
						| InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
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
	public PlaintextContainer symmetricDecrypt(AbstractSCCKey key, AbstractSCCCiphertext sccciphertext) {
		try {
			byte[] nonce = sccciphertext.parameters.nonce;
			int tagLength = sccciphertext.parameters.tagLength;
			String algo = sccciphertext.parameters.algo;

			Cipher cipher = Cipher.getInstance(algo);
			GCMParameterSpec spec = new GCMParameterSpec(tagLength, nonce);
			cipher.init(Cipher.DECRYPT_MODE, key, spec);
			byte[] decryptedCipher = cipher.doFinal(sccciphertext.ciphertext);
			String decryptedCipherText = new String(decryptedCipher, StandardCharsets.UTF_8);
			PlaintextContainer plainText = new PlaintextContainer(decryptedCipherText);
			return plainText;
		} catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException
				| InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchPaddingException e) {
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
	public SCCHash hash(PlaintextContainerInterface plaintext) {
		ArrayList<String> algorithms = new ArrayList<String>();

		// read our Algorithms for symmetric encryption out of JSON
		algorithms = JSONReader.getAlgos(CryptoUseCase.SymmetricEncryption);

		// get first one, later look what to do if first is not validate -> take next
		String alg = algorithms.get(0);

		String sccalgorithmID = "SHA3_512";

		// TODO mapping from sting to enum:

		if (getEnums().contains(sccalgorithmID)) {

			AlgorithmIDEnum chosenAlgorithmID = AlgorithmIDEnum.valueOf(sccalgorithmID);

			switch (chosenAlgorithmID) {
			case SHA3_512:
				try {
					// Get MessageDigest Instance
					MessageDigest messageDigest = MessageDigest.getInstance("SHA-512");

					// CREATE HASH
					byte[] hashBytes = messageDigest.digest(plaintext.getByteArray());
					SCCHash hash = new SCCHash(hashBytes);
					return hash;
				} catch (NoSuchAlgorithmException e) {
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
