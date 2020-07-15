package main;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;

import COSE.AlgorithmID;
import COSE.CoseException;
import COSE.OneKey;
import main.JSONReader.CryptoUseCase;
import main.SecureCryptoConfig.AlgorithmIDEnum;

/**
 * Class representing key pair that can be used for signing and asymmetric encryption.
 * @author Lisa
 *
 */
public class SCCKeyPair extends AbstractSCCKeyPair {
	
	//Use cases in which key pair can be used
	public enum KeyPairUseCase{
		AsymmetricEncryption, Signing
	}
	
	public enum SCCKeyPairAlgorithm {
		RSA, DiffieHellman, EC
	}

	/**
	 * Constructor that gets a KeyPair
	 * @param pair
	 */
	public SCCKeyPair(byte[] publicKey, byte[] privateKey, SCCKeyPairAlgorithm algorithm) {
		super(publicKey, privateKey, algorithm);
	}


	@Override
	public byte[] getPublicKeyBytes() {
		return this.publicKey;
	}

	
	@Override
	public byte[] getPrivateKeyBytes() {
		return this.privateKey;
	}
	
	protected PrivateKey getPrivateKey()
	{
		try {
			return KeyFactory.getInstance(this.algorithm.toString()).generatePrivate(new PKCS8EncodedKeySpec(this.privateKey));
		} catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	
	protected PublicKey getPublicKey()
	{
		try {
			return KeyFactory.getInstance(this.algorithm.toString()).generatePublic(new X509EncodedKeySpec(this.publicKey));
		} catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
        
	}
	
	protected KeyPair makeKeyPair()
	{
		return new KeyPair(getPublicKey(), getPrivateKey());
	}

	/**
	 * Creation of a key pair that can be used for signing or asymmetric encryption
	 * @param useCase
	 * @return SCCKeyPair
	 * @throws CoseException
	 * @throws NoSuchAlgorithmException
	 */
	public static SCCKeyPair createKeyPair(KeyPairUseCase useCase) throws CoseException, NoSuchAlgorithmException {
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

	/**
	 * Auxiliary method for creating SCCKeyPair
	 * @param c
	 * @return SCCKeyPair
	 * @throws NoSuchAlgorithmException
	 */
	private static SCCKeyPair createNewKeyPair(CryptoUseCase c) throws NoSuchAlgorithmException {
		ArrayList<String> algorithms = new ArrayList<String>();
		
		algorithms = JSONReader.getAlgos(c, SecureCryptoConfig.sccPath);

		for (int i = 0; i < algorithms.size(); i++) {

			String sccalgorithmID = algorithms.get(i);

			if (SecureCryptoConfig.getEnums().contains(sccalgorithmID)) {
				AlgorithmIDEnum chosenAlgorithmID = AlgorithmIDEnum.valueOf(sccalgorithmID);

				switch (chosenAlgorithmID) {
				// Asymmetric
				case RSA_SHA_512:
					return createAsymmetricKeyPair(SCCKeyPairAlgorithm.RSA, 4096);
				// Signing
				case ECDSA_512:
					try {
						OneKey oneKey = OneKey.generateKey(AlgorithmID.ECDSA_512);
						return new SCCKeyPair(oneKey.AsPublicKey().getEncoded(), oneKey.AsPrivateKey().getEncoded(), SCCKeyPairAlgorithm.EC);
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

	/**
	 * Auxiliary method for creating SCCKeyPair with specific size for asymmetric encryption
	 * @param algo
	 * @param keysize
	 * @return SCCKeyPair
	 */
	private static SCCKeyPair createAsymmetricKeyPair(SCCKeyPairAlgorithm algo, int keysize) {
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algo.toString());
			keyPairGenerator.initialize(keysize);
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			SCCKeyPair pair = new SCCKeyPair(keyPair.getPublic().getEncoded(), keyPair.getPrivate().getEncoded(), algo);
			return pair;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
	}


}
