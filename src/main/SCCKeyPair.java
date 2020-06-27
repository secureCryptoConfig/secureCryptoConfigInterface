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

	@Override
	PublicKey getPublic() {
		return this.pair.getPublic();
	}
	
	@Override
	PrivateKey getPrivate() {
		return this.pair.getPrivate();
	}
	

	@Override
	String getAlgorithm() {
		return this.algorithm;
	}


	@Override
	KeyPair getKeyPair() {
		return this.pair;
	}


	public static SCCKeyPair createAsymmetricKey() throws NoSuchAlgorithmException {
		ArrayList<String> algorithms = new ArrayList<String>();


		algorithms = JSONReader.getAlgos(CryptoUseCase.AsymmetricEncryption, ".\\src\\main\\" + SecureCryptoConfig.sccFileName);

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
			
		}
		throw new NoSuchAlgorithmException();
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
	
	public static SCCKeyPair createSigningKey() throws CoseException {
		ArrayList<String> algorithms = new ArrayList<String>();

		algorithms = JSONReader.getAlgos(CryptoUseCase.Signing, ".\\src\\main\\" + SecureCryptoConfig.sccFileName);

		for (int i = 0; i < algorithms.size(); i++) {

			// get first one, later look what to do if first is not validate -> take next
			String sccalgorithmID = algorithms.get(i);

			// TODO mapping from sting to enum:

			if (SecureCryptoConfig.getEnums().contains(sccalgorithmID)) {
				AlgorithmIDEnum chosenAlgorithmID = AlgorithmIDEnum.valueOf(sccalgorithmID);

				switch (chosenAlgorithmID) {
				case ECDSA_512:
					try {
						OneKey oneKey = OneKey.generateKey(AlgorithmID.ECDSA_512);
						KeyPair p = new KeyPair(oneKey.AsPublicKey(), oneKey.AsPrivateKey());
						return new SCCKeyPair(p, AlgorithmID.ECDSA_512.toString());
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
