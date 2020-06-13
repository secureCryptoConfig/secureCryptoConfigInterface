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

import main.JSONReader.CryptoUseCase;
import main.SecureCryptoConfig.AlgorithmIDEnum;

public class SCCKey extends main.AbstractSCCKey {


	protected SCCKey(SecretKey key, String algorithm) {
		super(key, algorithm);
	}

	/**
	protected SCCKey(byte[] key, String algorithm) {
		super(key, algorithm);
		// TODO Auto-generated constructor stub
	}
	**/
	@Override
	public SecretKey getKey()
	{
		return this.key;
	}
	public static SCCKey createKey() {

		// possible: AES, DES, DESede, HmacSHA1, HmacSHA256
		ArrayList<String> algorithms = new ArrayList<String>();
		// Default values
		int keysize = 256;
		String algo = "AES";

		algorithms = JSONReader.getAlgos(CryptoUseCase.SymmetricEncryption);

		for (int i = 0; i < algorithms.size(); i++) {

			String sccalgorithmID = algorithms.get(i);

			// TODO mapping from sting to enum:

			if (SecureCryptoConfig.getEnums().contains(sccalgorithmID)) {

				AlgorithmIDEnum chosenAlgorithmID = AlgorithmIDEnum.valueOf(sccalgorithmID);

				switch (chosenAlgorithmID) {
				case AES_GCM_256_96:
					algo = "AES";
					keysize = 256;
					return keyWithParams(algo, keysize);
				case AES_GCM_128_96:
					algo = "AES";
					keysize = 128;
					return keyWithParams(algo, keysize);
				default:
					break;

				}
			}
			// last round and no corresponding match in Switch case found
			// take default values for encryption
			if (i == (algorithms.size() - 1)) {
				System.out.println("No supported algorithms. Default values are used for key creation!");
				System.out.println("Used: " + algo);
				return keyWithParams(algo, keysize);

			}
		}

		return null;

	}

	public static SCCKey createKey(PlaintextContainer password) {

		// possible: AES, DES, DESede, HmacSHA1, HmacSHA256
		ArrayList<String> algorithms = new ArrayList<String>();
		// Default values
		int keysize = 256;
		String keyAlgo = "AES";
		String algo = "PBKDF2WithHmacSHA512";
		int saltLength = 64;
		int iterations = 1000;

		algorithms = JSONReader.getAlgos(CryptoUseCase.SymmetricEncryption);

		for (int i = 0; i < algorithms.size(); i++) {

			String sccalgorithmID = algorithms.get(i);

			// TODO mapping from sting to enum:

			if (SecureCryptoConfig.getEnums().contains(sccalgorithmID)) {

				AlgorithmIDEnum chosenAlgorithmID = AlgorithmIDEnum.valueOf(sccalgorithmID);

				switch (chosenAlgorithmID) {
				case AES_GCM_256_96:
					keyAlgo = "AES";
					keysize = 256;
					algo = "PBKDF2WithHmacSHA512";
					saltLength = 64;
					iterations = 1000;
					return keyWithPassword(password, algo, keyAlgo, keysize, iterations, saltLength);
				
				case AES_GCM_128_96:
					keyAlgo = "AES";
					keysize = 128;
					algo = "PBKDF2WithHmacSHA512";
					saltLength = 64;
					iterations = 1000;
					return keyWithPassword(password, algo, keyAlgo, keysize, iterations, saltLength);
				default:
					break;

				}
			}
			// last round and no corresponding match in Switch case found
			// take default values for encryption
			if (i == (algorithms.size() - 1)) {
				System.out.println("No supported algorithms. Default values are used for key creation!");
				System.out.println("Used: " + algo);
				return keyWithPassword(password, algo, keyAlgo, keysize, i, saltLength);

			}
		}

		return null;

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

	@Override
	String getAlgorithm() {
		return this.algorithm;
	}

	

}
