package main;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import main.JSONReader.CryptoUseCase;

public class SecureCryptoConfig implements SecureCryptoConfigInterface {


	// Only draft
	@Override
	public String symmetricEncrypt(SecretKey key, String plaintext) {
		
		ArrayList<String> algorithms = new ArrayList<String>();
		
		// read our Algorithms for symmetric encryption out of JSON
		algorithms = JSONReader.getAlgos(CryptoUseCase.SymmetricEncryption);
		
		// get first one, later look what to do if first is not validate -> take next
		String alg = algorithms.get(0);
		
		return doSymmetricEncryption(key, plaintext, alg);

	}



	private String doSymmetricEncryption(SecretKey key, String plainText, String alg) {
		//Split Algo Identifier in its parameters
		String [] parameters = alg.split("_");
		String algorithm = parameters[0];
		String mode = parameters[1];
		int keyLength = Integer.parseInt(parameters[2]);
		int tagLenth = Integer.parseInt(parameters[3]);
		int nonceLength = Integer.parseInt(parameters[4]);
		
		try {

			// ENCRYPTION
			Cipher cipher = Cipher.getInstance(algorithm + "/" + mode + "/NoPadding");
			
			// GENERATE random nonce (number used once)
			final byte[] nonce = UseCases.generateNonce(nonceLength);
			
			GCMParameterSpec spec = new GCMParameterSpec(tagLenth, nonce);
			cipher.init(Cipher.ENCRYPT_MODE, key, spec);

			byte[] byteCipher = cipher.doFinal(UseCases.getByte(plainText));
			// CONVERSION of raw bytes to BASE64 representation
			String cipherText = Base64.getEncoder().encodeToString(byteCipher);
			return cipherText;

		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
				| InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
			return null;
		}
		
	}



	@Override
	public SCCCiphertext symmetricReEncrypt(SCCKey key, SCCCiphertext ciphertext) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public PlaintextContainer symmetricDecrypt(SCCKey key, SCCCiphertext sccciphertext) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public SCCCiphertextStream<?> streamEncrypt(SCCKey key, PlaintextContainerStream<?> plaintext) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public SCCCiphertextStream<?> streamReEncrypt(SCCKey key, SCCCiphertextStream<?> ciphertext) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public PlaintextContainerStream<?> streamDecrypt(SCCKey key, SCCCiphertextStream<?> ciphertext) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public SCCCiphertext[] encrypt(SCCKey[] key, PlaintextContainer plaintext) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public SCCCiphertext asymmetricEncrypt(SCCKey key, PlaintextContainer plaintext) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public SCCCiphertext AsymmetricReEncrypt(SCCKey key, SCCCiphertext ciphertext) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public PlaintextContainer asymmetricDecrypt(SCCKey key, SCCCiphertext ciphertext) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public SCCHash hash(PlaintextContainer plaintext) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public SCCHash reHash(PlaintextContainer plaintext) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean verifyHash(PlaintextContainer plaintext, SCCHash hash) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public SCCSignature sign(SCCKey privateKey, PlaintextContainer plaintext) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public SCCSignature reSign(SCCKey privateKey, PlaintextContainer plaintext) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean validteSignature(SCCKey publicKeyy, SCCSignature signature) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public SCCPasswordHash passwordHash(String password) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean verifyPassword(String password, SCCPasswordHash passwordhash) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public SCCKey generateKey() {
		// TODO Auto-generated method stub
		return null;
	}
	

	
}
