package org.securecryptoconfig;

import java.util.ArrayList;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility;

/**
 * Class for JSON file processing. Needed for parsing the Secure Crypto Config files.
 * Auxiliary class for {@link SCCInstance} as multiple different Usecases with different
 * algorithms can be specified. 
 * @author Lisa
 *
 */
@JsonAutoDetect(fieldVisibility = Visibility.ANY)
public class SCCInstanceUseCase {

	private ArrayList<SecureCryptoConfig.SCCAlgorithm> SymmetricEncryption;
	private ArrayList<SecureCryptoConfig.SCCAlgorithm> AsymmetricEncryption;
	private ArrayList<SecureCryptoConfig.SCCAlgorithm> Hashing;
	private ArrayList<SecureCryptoConfig.SCCAlgorithm> Signing;
	private ArrayList<SecureCryptoConfig.SCCAlgorithm> PasswordHashing;
	
	protected ArrayList<SecureCryptoConfig.SCCAlgorithm> getSymmetricEncryption() {
		return SymmetricEncryption;
	}
	protected void setSymmetricEncryption(ArrayList<SecureCryptoConfig.SCCAlgorithm> symmetricEncryption) {
		SymmetricEncryption = symmetricEncryption;
	}
	protected ArrayList<SecureCryptoConfig.SCCAlgorithm> getAsymmetricEncryption() {
		return AsymmetricEncryption;
	}
	protected void setAsymmetricEncryption(ArrayList<SecureCryptoConfig.SCCAlgorithm> asymmetricEncryption) {
		AsymmetricEncryption = asymmetricEncryption;
	}
	protected ArrayList<SecureCryptoConfig.SCCAlgorithm> getHashing() {
		return Hashing;
	}
	protected void setHashing(ArrayList<SecureCryptoConfig.SCCAlgorithm> hashing) {
		Hashing = hashing;
	}
	protected ArrayList<SecureCryptoConfig.SCCAlgorithm> getSigning() {
		return Signing;
	}
	protected void setSigning(ArrayList<SecureCryptoConfig.SCCAlgorithm> signing) {
		Signing = signing;
	}
	protected ArrayList<SecureCryptoConfig.SCCAlgorithm> getPasswordHashing() {
		return PasswordHashing;
	}
	protected void setPasswordHashing(ArrayList<SecureCryptoConfig.SCCAlgorithm> passwordHashing) {
		PasswordHashing = passwordHashing;
	}
}
