package main;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

import COSE.AlgorithmID;
import COSE.CoseException;
import COSE.OneKey;
import main.JSONReader.CryptoUseCase;
import main.SecureCryptoConfig.AlgorithmIDEnum;

public class SCCKeyPair extends AbstractSCCKeyPair {
	
	public enum keyPairUseCase{
		AsymmetricEncryption, Signing
	}

	public SCCKeyPair(KeyPair pair) {
		super(pair);
	}


	@Override
	public byte[] getPublicKeyBytes() {
		return this.pair.getPublic().getEncoded();
	}

	
	@Override
	public byte[] getPrivateKeyBytes() {
		return this.pair.getPrivate().getEncoded();
	}

	public static SCCKeyPair createKeyPair(keyPairUseCase useCase) throws CoseException, NoSuchAlgorithmException {
		CryptoUseCase c;
		switch (useCase) {
		case Signing:
			c = CryptoUseCase.Signing;
			return createNewKeyPair(c);
		case AsymmetricEncryption:
			c = CryptoUseCase.AsymmetricEncryption;
			return createNewKeyPair(c);
		default:
			return null;
		}
	}

	private static SCCKeyPair createNewKeyPair(CryptoUseCase c) throws NoSuchAlgorithmException {
		ArrayList<String> algorithms = new ArrayList<String>();
		
		algorithms = JSONReader.getAlgos(c, JSONReader.basePath + SecureCryptoConfig.sccFileName);

		for (int i = 0; i < algorithms.size(); i++) {

			// get first one, later look what to do if first is not validate -> take next
			String sccalgorithmID = algorithms.get(i);

			// TODO mapping from sting to enum:

			if (SecureCryptoConfig.getEnums().contains(sccalgorithmID)) {
				AlgorithmIDEnum chosenAlgorithmID = AlgorithmIDEnum.valueOf(sccalgorithmID);

				switch (chosenAlgorithmID) {
				// Asymmetric
				case RSA_SHA_512:
					return createAsymmetricKeyPair("RSA", 4096);
				// Signing
				case ECDSA_512:
					try {
						OneKey oneKey = OneKey.generateKey(AlgorithmID.ECDSA_512);
						return new SCCKeyPair(new KeyPair(oneKey.AsPublicKey(), oneKey.AsPrivateKey()));
					} catch (CoseException e) {
						e.printStackTrace();
					}
				default:
					break;
				}
			}

		}
		throw new NoSuchAlgorithmException();
	}

	private static SCCKeyPair createAsymmetricKeyPair(String algo, int keysize) {
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algo);
			keyPairGenerator.initialize(keysize);
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			SCCKeyPair pair = new SCCKeyPair(keyPair);
			return pair;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
	}


}
