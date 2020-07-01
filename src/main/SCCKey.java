package main;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.ArrayList;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import COSE.CoseException;
import main.JSONReader.CryptoUseCase;
import main.SecureCryptoConfig.AlgorithmIDEnum;

public class SCCKey extends AbstractSCCKey {

	public enum SCCKeyAlgorithm {
		AES, Blowfish, ARCFOUR, DES, DESede, HmacMD5, HmacSHA1, HmacSHA224, HmacSHA256, HmacSHA384, HmacSHA512, RC2
	}

	public SCCKey(byte[] key, SCCKeyAlgorithm algorithm) {
		super(key, algorithm);
	}

	@Override
	public SecretKey getSecretKey() {
		return new SecretKeySpec(key, 0, key.length, this.algorithm.toString());
	}

	@Override
	public byte[] getByteArray() {
		return this.key;
	}

	@Override
	public String getAlgorithm() {
		return this.algorithm.toString();
	}

	public static SCCKey createKey(PlaintextContainer password) throws CoseException {
		String algo = null;
		SCCKeyAlgorithm keyAlgo = null;
		int keysize = 0, iterations = 0, saltLength = 0;

		ArrayList<String> algorithms = new ArrayList<String>();
		
		algorithms = JSONReader.getAlgos(CryptoUseCase.SymmetricEncryption,
				JSONReader.basePath + SecureCryptoConfig.sccFileName);

		for (int i = 0; i < algorithms.size(); i++) {

			String sccalgorithmID = algorithms.get(i);

			// TODO mapping from sting to enum:

			if (SecureCryptoConfig.getEnums().contains(sccalgorithmID)) {

				AlgorithmIDEnum chosenAlgorithmID = AlgorithmIDEnum.valueOf(sccalgorithmID);

				switch (chosenAlgorithmID) {
				case AES_GCM_256_96:
					algo = "PBKDF2WithHmacSHA512";
					keyAlgo = SCCKeyAlgorithm.AES;
					keysize = 256;
					iterations = 10000;
					saltLength = 64;
					break;
				case AES_GCM_128_96:
					algo = "PBKDF2WithHmacSHA512";
					keyAlgo = SCCKeyAlgorithm.AES;
					keysize = 128;
					iterations = 10000;
					saltLength = 64;
					break;
				default:
					break;

				}
				try {

					byte[] salt = UseCases.generateRandomByteArray(saltLength);

					SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(algo);
					KeySpec passwordBasedEncryptionKeySpec = new PBEKeySpec(password.getBase64().toCharArray(), salt,
							iterations, keysize);
					SecretKey secretKeyFromPBKDF2 = secretKeyFactory.generateSecret(passwordBasedEncryptionKeySpec);
					SecretKey key = new SecretKeySpec(secretKeyFromPBKDF2.getEncoded(), keyAlgo.toString());
					return new SCCKey(key.getEncoded(), keyAlgo);
				} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
					e.printStackTrace();
					return null;

				}

			}

		}

		throw new CoseException("No supported algorithms! Key creation not possible!");

	}

}
