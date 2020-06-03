package main;
import java.util.ArrayList;

import COSE.*;
import main.JSONReader.CryptoUseCase;


public class SecureCryptoConfig implements SecureCryptoConfigInterface {
	
	//needed
	public enum Algorithms {
		AES_GCM_256_128_128,
        AES_GCM_256_256_128,
        AES_CCM_64_128_128,
        AES_CCM_64_128_256
	}

	@Override
	public SCCCiphertext symmetricEncrypt(SCCKey key, PlaintextContainer plaintext) throws CoseException {
		ArrayList<String> algos = new ArrayList<String>();
		algos = JSONReader.getAlgos(CryptoUseCase.SymmetricEncryption);
		String alg = algos.get(0);
		switch (alg) {
        case "AES_GCM_256_128_128":
        case "AES_GCM_256_256_128":
            AES_GCM_Encrypt(alg, key, plaintext);
            break;

        case "AES_CCM_64_128_128":
        case "AES_CCM_64_128_256":
            AES_CCM_Encrypt(alg, key, plaintext);
            break;

        default:
            throw new CoseException("Unsupported Algorithm Specified");
    }
		return null;
	}



	private void AES_CCM_Encrypt(String alg, SCCKey key, PlaintextContainer plaintext) {
		// TODO Auto-generated method stub
		
	}



	private void AES_GCM_Encrypt(String alg, SCCKey key, PlaintextContainer plaintext) {
		// TODO Auto-generated method stub
		
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
	

}
