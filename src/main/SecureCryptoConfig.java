package main;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.HashSet;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;

import main.JSONReader.CryptoUseCase;

public class SecureCryptoConfig implements SecureCryptoConfigInterface {

	ArrayList<String> algorithms = new ArrayList<String>();

	// TODO refactor in separate class?
	static enum AlgorithmIDEnum {
		AES_GCM_256_128_128, AES_GCM_256_128_256, SHA3_512, RSA_SHA3_256, RSA_SHA3_512
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

		int nonceLength, tagLength;
		String algo;

		algorithms = JSONReader.getAlgos(CryptoUseCase.SymmetricEncryption);

		// get first one, later look what to do if first is not validate -> take next
		String sccalgorithmID = algorithms.get(1);

		// TODO mapping from sting to enum:

		if (getEnums().contains(sccalgorithmID)) {

			AlgorithmIDEnum chosenAlgorithmID = AlgorithmIDEnum.valueOf(sccalgorithmID);

			switch (chosenAlgorithmID) {
			case AES_GCM_256_128_128:
				nonceLength = 16;
				tagLength = 128;
				algo = "AES/GCM/NoPadding";
				return UseCases.symmetricEncryptWithParams(key, plaintext, nonceLength, tagLength, algo);

			case AES_GCM_256_128_256:
				nonceLength = 32;
				tagLength = 128;
				algo = "AES/GCM/NoPadding";
				return UseCases.symmetricEncryptWithParams(key, plaintext, nonceLength, tagLength, algo);
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
	public SCCCiphertext asymmetricEncrypt(AbstractSCCKeyPair keyPair, PlaintextContainerInterface plaintext) {

		String algo;

		algorithms = JSONReader.getAlgos(CryptoUseCase.AsymmetricEncryption);

		// get first one, later look what to do if first is not validate -> take next
		String sccalgorithmID = algorithms.get(0);

		// TODO mapping from sting to enum:

		if (getEnums().contains(sccalgorithmID)) {

			AlgorithmIDEnum chosenAlgorithmID = AlgorithmIDEnum.valueOf(sccalgorithmID);

			switch (chosenAlgorithmID) {
			case RSA_SHA3_256:
				algo = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
				return UseCases.asymmetricEncryptWithParams(keyPair, plaintext, algo);

			default:
				return null;
			}
		}
		return null;
	}

	@Override
	public PlaintextContainer asymmetricDecrypt(AbstractSCCKeyPair keyPair, AbstractSCCCiphertext ciphertext) {
		try {
			Cipher cipher = Cipher.getInstance(ciphertext.parameters.algo);
			cipher.init(Cipher.DECRYPT_MODE, keyPair.privateKey);
			byte[] decryptedCipher = cipher.doFinal(ciphertext.ciphertext);
			String decryptedCipherText = new String(decryptedCipher, StandardCharsets.UTF_8);
			PlaintextContainer decrypted = new PlaintextContainer(decryptedCipherText);
			return decrypted;
		} catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException | NoSuchAlgorithmException
				| NoSuchPaddingException e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public AbstractSCCCiphertext asymmetricReEncrypt(AbstractSCCKeyPair keyPair, AbstractSCCCiphertext ciphertext) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public SCCHash hash(PlaintextContainerInterface plaintext) {

		String algo;

		// read our Algorithms for symmetric encryption out of JSON
		algorithms = JSONReader.getAlgos(CryptoUseCase.Hashing);

		// get first one, later look what to do if first is not validate -> take next
		String sccalgorithmID = algorithms.get(0);

		// TODO mapping from sting to enum:

		if (getEnums().contains(sccalgorithmID)) {

			AlgorithmIDEnum chosenAlgorithmID = AlgorithmIDEnum.valueOf(sccalgorithmID);

			switch (chosenAlgorithmID) {
			case SHA3_512:
				algo = "SHA-512";
				return UseCases.hashingWithParams(plaintext, algo);
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
		// Hash same plain two times and look if it is the same
		SCCHash hash1 = hash(plaintext);
		return hash.toString().equals(hash1.toString());
	}

	@Override
	public SCCSignature sign(AbstractSCCKeyPair keyPair, PlaintextContainerInterface plaintext) {
		String algo;

		// read our Algorithms for symmetric encryption out of JSON
		algorithms = JSONReader.getAlgos(CryptoUseCase.Signing);

		// get first one, later look what to do if first is not validate -> take next
		String sccalgorithmID = algorithms.get(0);

		// TODO mapping from sting to enum:

		if (getEnums().contains(sccalgorithmID)) {

			AlgorithmIDEnum chosenAlgorithmID = AlgorithmIDEnum.valueOf(sccalgorithmID);

			switch (chosenAlgorithmID) {
			case RSA_SHA3_512:
				algo = "SHA512withRSA";
				return UseCases.signingingWithParams(keyPair, plaintext, algo);

			default:
				return null;
			}
		}
		return null;
	}

	@Override
	public AbstractSCCSignature reSign(AbstractSCCKeyPair keyPair, PlaintextContainerInterface plaintext) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean validateSignature(AbstractSCCKeyPair keyPair, AbstractSCCSignature signature) {

		try {
			Signature s = Signature.getInstance(signature.parameters.algo);
			s.initVerify((PublicKey) keyPair.publicKey);
			s.update(signature.parameters.plain.getByteArray());
			return s.verify(signature.signature);
			
		} catch (InvalidKeyException | SignatureException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
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
