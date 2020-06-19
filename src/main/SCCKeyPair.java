package main;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;

import COSE.AlgorithmID;
import COSE.CoseException;
import COSE.OneKey;
import main.JSONReader.CryptoUseCase;
import main.SecureCryptoConfig.AlgorithmIDEnum;

public class SCCKeyPair extends AbstractSCCKeyPair {

	protected SCCKeyPair(KeyPair pair, String algorithm) {
		super(pair, algorithm);
	}

	protected PublicKey getPublic() {
		return this.pair.getPublic();
	}
	
	protected PrivateKey getPrivate() {
		return this.pair.getPrivate();
	}

	/**
	public static SCCKeyPair createKeyPair(CryptoUseCase useCase) {

		// possible values: DiffieHellman, DSA, RSA
		
		if (useCase == CryptoUseCase.AsymmetricEncryption) {
			return createAsymmetricKey();
		} else if (useCase == CryptoUseCase.Signing) {
			return createSigningKey();
		} else {
			System.out.println("Not right Method for key creation for your UseCase");
			return null;
		}

	}
	**/

	public static SCCKeyPair createAsymmetricKey() {
		ArrayList<String> algorithms = new ArrayList<String>();

		// Default value
		String algo = "RSA";
		int keysize = 4096;

		algorithms = JSONReader.getAlgos(CryptoUseCase.AsymmetricEncryption);

		for (int i = 0; i < algorithms.size(); i++) {

			// get first one, later look what to do if first is not validate -> take next
			String sccalgorithmID = algorithms.get(i);

			// TODO mapping from sting to enum:

			if (SecureCryptoConfig.getEnums().contains(sccalgorithmID)) {
				AlgorithmIDEnum chosenAlgorithmID = AlgorithmIDEnum.valueOf(sccalgorithmID);

				switch (chosenAlgorithmID) {
				case RSA_SHA_256:
					return keyPairWithParams("RSA", 4096);

				default:
					break;
				}
			}
			// last round and no corresponding match in Switch case found
			// take default values for generation
			if (i == (algorithms.size() - 1)) {
				System.out.println("No supported algorithms. Default values are used for key generation!");
				System.out.println("Used: " + algo);
				return keyPairWithParams(algo, keysize);
			}
		}
		return null;
	}
	
	private static SCCKeyPair keyPairWithParams(String algo, int keysize) {
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algo);
			keyPairGenerator.initialize(keysize);
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			SCCKeyPair pair = new SCCKeyPair(keyPair, algo);
			return pair;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	public static OneKey createSigningKey() throws CoseException {
		ArrayList<String> algorithms = new ArrayList<String>();

		algorithms = JSONReader.getAlgos(CryptoUseCase.Signing);

		for (int i = 0; i < algorithms.size(); i++) {

			// get first one, later look what to do if first is not validate -> take next
			String sccalgorithmID = algorithms.get(i);

			// TODO mapping from sting to enum:

			if (SecureCryptoConfig.getEnums().contains(sccalgorithmID)) {
				AlgorithmIDEnum chosenAlgorithmID = AlgorithmIDEnum.valueOf(sccalgorithmID);

				switch (chosenAlgorithmID) {
				case ECDSA_512:
					try {
						return OneKey.generateKey(AlgorithmID.ECDSA_512);
					} catch (CoseException e) {
						e.printStackTrace();
					}
				default:
					break;
				}
			}
			
		}
		throw new CoseException("No supported algorithm for key Generation!");
	}

	

}
