package main;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
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

/**
 * Class representing Key that is needed for symmetric encryption
 * @author Lisa
 *
 */
public class SCCKey extends AbstractSCCKey {

	//Enum containing all currently supproted algorithms for key creation from Java
	public enum SCCKeyAlgorithm {
		AES, Blowfish, ARCFOUR, DES, DESede, HmacMD5, HmacSHA1, HmacSHA224, HmacSHA256, HmacSHA384, HmacSHA512, RC2
	}

	/**
	 * Constructor which gets the byte[] representation of the key and the algorithm of its creation
	 * @param key
	 * @param algorithm
	 */
	public SCCKey(byte[] key, SCCKeyAlgorithm algorithm) {
		super(key, algorithm);
	}

	@Override
	public byte[] toBytes() {
		return this.key;
	}
	
	protected SecretKey getSecretKey() {
		return new SecretKeySpec(key, 0, key.length, this.algorithm.toString());
	}

	/**
	 * Creation of key derivend from a given password that can be used for symmetric encryption
	 * @param password
	 * @return SCCKey
	 */
	public static SCCKey createKeyWithPassword(byte[] password)
	{
		try {
			return createKeyWithPassword(new PlaintextContainer(password));
			
		}catch(CoseException e)
		{
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Creation of key derivend from a given password that can be used for symmetric encryption
	 * @param password
	 * @return SCCKey
	 * @throws CoseException
	 */
	public static SCCKey createKeyWithPassword(PlaintextContainer password) throws CoseException {
		String algo = null;
		SCCKeyAlgorithm keyAlgo = null;
		int keysize = 0, iterations = 0, saltLength = 0;

		ArrayList<String> algorithms = new ArrayList<String>();
		
		algorithms = JSONReader.getAlgos(CryptoUseCase.SymmetricEncryption,
				SecureCryptoConfig.sccPath);

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

					byte[] salt = generateRandomByteArray(saltLength);

					SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(algo);
					KeySpec passwordBasedEncryptionKeySpec = new PBEKeySpec(password.toString(StandardCharsets.UTF_8).toCharArray(), salt,
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
	
	/**
	 * Creation of a key that can be used for symmetric encryption
	 * @return SCCKey
	 * @throws CoseException
	 */
	public static SCCKey createSymmetricKey() throws CoseException {

		SCCKeyAlgorithm algo = null;
		int keysize = 0;
		
		ArrayList<String> algorithms = new ArrayList<String>();

		algorithms = JSONReader.getAlgos(CryptoUseCase.SymmetricEncryption, SecureCryptoConfig.sccPath);
		for (int i = 0; i < algorithms.size(); i++) {

			String sccalgorithmID = algorithms.get(i);

			// TODO mapping from sting to enum:

			if (SecureCryptoConfig.getEnums().contains(sccalgorithmID)) {

				AlgorithmIDEnum chosenAlgorithmID = AlgorithmIDEnum.valueOf(sccalgorithmID);

				switch (chosenAlgorithmID) {
				case AES_GCM_256_96:
					algo = SCCKeyAlgorithm.AES;
					keysize = 256;
					break;
				case AES_GCM_128_96:
					algo = SCCKeyAlgorithm.AES;
					keysize = 128;
					break;
				default:
					break;

				}

				KeyGenerator keyGen;
				try {
					keyGen = KeyGenerator.getInstance(algo.toString());
					keyGen.init(keysize);
					SecretKey key = keyGen.generateKey();
					return new SCCKey(key.getEncoded(), algo);
				} catch (NoSuchAlgorithmException e) {
					e.printStackTrace();
					return null;
				}
			}

		}

		throw new CoseException("No supported algorithms! Key creation not possible!");

	}
	

	/**
	 * Generate byte[] with secure Random number generator
	 * @param length
	 * @return byte[]
	 */
	private static byte[] generateRandomByteArray(int length) {
		try {
			final byte[] nonce = new byte[length];
			SecureRandom random;
			random = SecureRandom.getInstanceStrong();
			random.nextBytes(nonce);
			return nonce;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}

	}



}
