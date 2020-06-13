package main;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
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
import javax.crypto.CipherInputStream;
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

	protected static HashSet<String> getEnums() {
		HashSet<String> values = new HashSet<String>();

		for (AlgorithmIDEnum c : AlgorithmIDEnum.values()) {
			values.add(c.name());
		}

		return values;
	}

	@Override
	public SCCCiphertext symmetricEncrypt(AbstractSCCKey key, PlaintextContainerInterface plaintext) {

		// Default Values : AES_GCM_256_128_128
		int nonceLength = 16;
		int tagLength = 128;
		String algo = "AES/GCM/NoPadding";

		algorithms = JSONReader.getAlgos(CryptoUseCase.SymmetricEncryption);

		// get first one, later look what to do if first is not validate -> take next
		for (int i = 0; i < algorithms.size(); i++) {

			String sccalgorithmID = algorithms.get(i);

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
					break;

				}
			}
			// last round and no corresponding match in Switch case found
			// take default values for encryption
			if (i == (algorithms.size() - 1)) {
				System.out.println("No supported algorithms. Default values are used for encryption!");
				System.out.println("Used: " + AlgorithmIDEnum.AES_GCM_256_128_128);
				return UseCases.symmetricEncryptWithParams(key, plaintext, nonceLength, tagLength, algo);

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
			cipher.init(Cipher.DECRYPT_MODE, key.key, spec);
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
	public SCCCiphertext streamEncrypt(AbstractSCCKey key, String filepath) {
		// Default Values : AES_GCM_256_128_128
		int nonceLength = 16;
		int tagLength = 128;
		String algo = "AES/GCM/NoPadding";

		algorithms = JSONReader.getAlgos(CryptoUseCase.SymmetricEncryption);

		for (int i = 0; i < algorithms.size(); i++) {

			// get first one, later look what to do if first is not validate -> take next
			String sccalgorithmID = algorithms.get(i);

			// TODO mapping from sting to enum:

			if (getEnums().contains(sccalgorithmID)) {

				AlgorithmIDEnum chosenAlgorithmID = AlgorithmIDEnum.valueOf(sccalgorithmID);

				switch (chosenAlgorithmID) {
				case AES_GCM_256_128_128:
					nonceLength = 16;
					tagLength = 128;
					algo = "AES/GCM/NoPadding";
					return UseCases.fileEncryptWithParams(key, filepath, nonceLength, tagLength, algo);

				case AES_GCM_256_128_256:
					nonceLength = 32;
					tagLength = 128;
					algo = "AES/GCM/NoPadding";
					return UseCases.fileEncryptWithParams(key, filepath, nonceLength, tagLength, algo);
				default:
					break;

				}
			}
			// last round and no corresponding match in Switch case found
			// take default values for encryption
			if (i == (algorithms.size() - 1)) {
				System.out.println("No supported algorithms. Default values are used for encryption!");
				System.out.println("Used: " + AlgorithmIDEnum.AES_GCM_256_128_128);
				return UseCases.fileEncryptWithParams(key, filepath, nonceLength, tagLength, algo);
			}
		}
		return null;
	}

	@Override
	public AbstractSCCCiphertext streamReEncrypt(AbstractSCCKey key, String filepath) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public PlaintextContainer streamDecrypt(AbstractSCCKey key, AbstractSCCCiphertext ciphertext, String filepath) {
		String decryptedCipherText;
		try {

			Cipher cipher = Cipher.getInstance(ciphertext.parameters.algo);
			GCMParameterSpec spec = new GCMParameterSpec(ciphertext.parameters.tagLength, ciphertext.parameters.nonce);
			cipher.init(Cipher.DECRYPT_MODE, key.key, spec);
			
			FileInputStream fileInputStream = new FileInputStream(filepath);
	        CipherInputStream cipherInputStream = new CipherInputStream(fileInputStream, cipher);
	        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
	      
	        byte[] buffer = new byte[8192];
	        int nread;
	        while ((nread = cipherInputStream.read(buffer)) > 0) {
	          byteArrayOutputStream.write(buffer, 0, nread);
	        }
	        FileOutputStream fileOutputStream = new FileOutputStream(filepath);
	        fileOutputStream.write(buffer);
	        
	        fileOutputStream.close();
	        byteArrayOutputStream.flush();
	        cipherInputStream.close();
		
	        decryptedCipherText = new String(byteArrayOutputStream.toByteArray(), StandardCharsets.UTF_8);
	        
	        PlaintextContainer p = new PlaintextContainer(decryptedCipherText);
			return p;
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | IOException | InvalidKeyException
				| InvalidAlgorithmParameterException e) {

			e.printStackTrace();
		}
		return null;
	}

	@Override
	public AbstractSCCCiphertext[] encrypt(AbstractSCCKey[] key, PlaintextContainerInterface plaintext) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public SCCCiphertext asymmetricEncrypt(AbstractSCCKeyPair keyPair, PlaintextContainerInterface plaintext) {
		// Default Values : RSA_SHA3_256
		String algo = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

		algorithms = JSONReader.getAlgos(CryptoUseCase.AsymmetricEncryption);

		for (int i = 0; i < algorithms.size(); i++) {

			// get first one, later look what to do if first is not validate -> take next
			String sccalgorithmID = algorithms.get(i);

			// TODO mapping from sting to enum:

			if (getEnums().contains(sccalgorithmID)) {

				AlgorithmIDEnum chosenAlgorithmID = AlgorithmIDEnum.valueOf(sccalgorithmID);

				switch (chosenAlgorithmID) {
				case RSA_SHA3_256:
					algo = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
					return UseCases.asymmetricEncryptWithParams(keyPair, plaintext, algo);

				default:
					break;
				}
			}
			// last round and no corresponding match in Switch case found
			// take default values for encryption
			if (i == (algorithms.size() - 1)) {
				System.out.println("No supported algorithms. Default values are used for encryption!");
				System.out.println("Used: " + AlgorithmIDEnum.RSA_SHA3_256);
				return UseCases.asymmetricEncryptWithParams(keyPair, plaintext, algo);
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

		// Default Values : SHA3_512
		String algo = "SHA-512";

		// read our Algorithms for symmetric encryption out of JSON
		algorithms = JSONReader.getAlgos(CryptoUseCase.Hashing);

		for (int i = 0; i < algorithms.size(); i++) {
			// get first one, later look what to do if first is not validate -> take next
			String sccalgorithmID = algorithms.get(i);

			// TODO mapping from sting to enum:

			if (getEnums().contains(sccalgorithmID)) {

				AlgorithmIDEnum chosenAlgorithmID = AlgorithmIDEnum.valueOf(sccalgorithmID);

				switch (chosenAlgorithmID) {
				case SHA3_512:
					algo = "SHA-512";
					return UseCases.hashingWithParams(plaintext, algo);
				default:
					break;
				}
			}
			// last round and no corresponding match in Switch case found
			// take default values for hashing
			if (i == (algorithms.size() - 1)) {
				System.out.println("No supported algorithms. Default values are used for hashing!");
				System.out.println("Used: " + AlgorithmIDEnum.SHA3_512);
				return UseCases.hashingWithParams(plaintext, algo);
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
		// Default Values : RSA_SHA3_512
		String algo = "SHA512withRSA";

		// read our Algorithms for symmetric encryption out of JSON
		algorithms = JSONReader.getAlgos(CryptoUseCase.Signing);

		for (int i = 0; i < algorithms.size(); i++) {
			// get first one, later look what to do if first is not validate -> take next
			String sccalgorithmID = algorithms.get(i);

			// TODO mapping from sting to enum:

			if (getEnums().contains(sccalgorithmID)) {

				AlgorithmIDEnum chosenAlgorithmID = AlgorithmIDEnum.valueOf(sccalgorithmID);

				switch (chosenAlgorithmID) {
				case RSA_SHA3_512:
					algo = "SHA512withRSA";
					return UseCases.signingingWithParams(keyPair, plaintext, algo);

				default:
					break;
				}
			}
			// last round and no corresponding match in Switch case found
			// take default values for hashing
			if (i == (algorithms.size() - 1)) {
				System.out.println("No supported algorithms. Default values are used for signing!");
				System.out.println("Used: " + AlgorithmIDEnum.RSA_SHA3_512);
				return UseCases.signingingWithParams(keyPair, plaintext, algo);

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
