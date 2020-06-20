package main;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.ArrayList;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import COSE.CoseException;
import main.JSONReader.CryptoUseCase;
import main.SecureCryptoConfig.AlgorithmIDEnum;

public class SCCKey extends main.AbstractSCCKey {

	protected SCCKey(SecretKey key, String algorithm) {
		super(key, algorithm);
	}

	/**
	 * protected SCCKey(byte[] key, String algorithm) { super(key, algorithm); //
	 * TODO Auto-generated constructor stub }
	 **/
	@Override
	public SecretKey getKey() {
		return this.key;
	}
	
	@Override
	String getAlgorithm() {
		return this.algorithm;
	}

	public static SCCKey createKey() throws CoseException {

		// possible: AES, DES, DESede, HmacSHA1, HmacSHA256
		ArrayList<String> algorithms = new ArrayList<String>();

		algorithms = JSONReader.getAlgos(CryptoUseCase.SymmetricEncryption, ".\\src\\main\\" + SecureCryptoConfig.sccFileName );

		for (int i = 0; i < algorithms.size(); i++) {

			String sccalgorithmID = algorithms.get(i);

			// TODO mapping from sting to enum:

			if (SecureCryptoConfig.getEnums().contains(sccalgorithmID)) {

				AlgorithmIDEnum chosenAlgorithmID = AlgorithmIDEnum.valueOf(sccalgorithmID);

				switch (chosenAlgorithmID) {
				case AES_GCM_256_96:
					return keyWithParams("AES", 256);
				case AES_GCM_128_96:
					return keyWithParams("AES", 128);
				default:
					break;

				}
			}

		}

		throw new CoseException("No supported algorithms! Key creation not possible!");

	}

	public static SCCKey createKey(PlaintextContainer password) throws CoseException {

		// possible: AES, DES, DESede, HmacSHA1, HmacSHA256
		ArrayList<String> algorithms = new ArrayList<String>();
		
		algorithms = JSONReader.getAlgos(CryptoUseCase.SymmetricEncryption, ".\\src\\main\\" + SecureCryptoConfig.sccFileName);

		for (int i = 0; i < algorithms.size(); i++) {

			String sccalgorithmID = algorithms.get(i);

			// TODO mapping from sting to enum:

			if (SecureCryptoConfig.getEnums().contains(sccalgorithmID)) {

				AlgorithmIDEnum chosenAlgorithmID = AlgorithmIDEnum.valueOf(sccalgorithmID);

				switch (chosenAlgorithmID) {
				case AES_GCM_256_96:
					return keyWithPassword(password, "PBKDF2WithHmacSHA512", "AES", 256, 10000, 64);

				case AES_GCM_128_96:
					return keyWithPassword(password, "PBKDF2WithHmacSHA512", "AES", 128, 10000, 64);
				default:
					break;

				}
			}

		}

		throw new CoseException("No supported algorithms! Key creation not possible!");

	}

	private static SCCKey keyWithPassword(PlaintextContainer password, String algo, String keyAlgo, int keysize,
			int iterations, int saltLength) {

		try {

			byte[] salt = UseCases.generateRandomByteArray(saltLength);

			SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(algo);
			KeySpec passwordBasedEncryptionKeySpec = new PBEKeySpec(password.getPlain().toCharArray(), salt, iterations,
					keysize);
			SecretKey secretKeyFromPBKDF2 = secretKeyFactory.generateSecret(passwordBasedEncryptionKeySpec);
			SecretKey key = new SecretKeySpec(secretKeyFromPBKDF2.getEncoded(), keyAlgo);
			return new SCCKey(key, algo);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			e.printStackTrace();
			return null;

		}

	}

	private static SCCKey keyWithParams(String algo, int keysize) {
		KeyGenerator keyGen;
		try {
			keyGen = KeyGenerator.getInstance(algo);
			keyGen.init(keysize);
			SecretKey key = keyGen.generateKey();
			return new SCCKey(key, algo);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
	}



}
