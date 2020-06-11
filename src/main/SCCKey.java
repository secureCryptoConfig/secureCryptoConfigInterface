package main;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import main.JSONReader.CryptoUseCase;
import main.SecureCryptoConfig.AlgorithmIDEnum;

public class SCCKey extends main.AbstractSCCKey {

	private static final long serialVersionUID = 1L;

	protected SCCKey(byte[] key, String algorithm) {
		super(key, algorithm);
		// TODO Auto-generated constructor stub
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
				case AES_GCM_256_128_128:
				case AES_GCM_256_128_256:
					algo = "AES";
					keysize = 256;
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

			}
		}

		return null;

	}

	private static SCCKey keyWithParams(String algo, int keysize) {
		KeyGenerator keyGen;
		try {
			keyGen = KeyGenerator.getInstance(algo);
			keyGen.init(keysize);
			SecretKey key = keyGen.generateKey();
			return new SCCKey(key.getEncoded(), algo);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
	}

	@Override
	String getDefaultAlgorithm() {
		return this.getAlgorithm();
	}

}
