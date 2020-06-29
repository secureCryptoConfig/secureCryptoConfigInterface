package main;

import java.nio.charset.Charset;
import java.util.Base64;

import COSE.CoseException;

public class PlaintextContainer implements PlaintextContainerInterface {

	private byte[] plaintext;
	SecureCryptoConfig scc = new SecureCryptoConfig();
	
	public PlaintextContainer(byte[] plaintext) {
		this.plaintext = plaintext;
	}
	

	@Override
	public byte[] getByteArray() {
		return plaintext;
	}

	@Override
	public String getBase64() {
		return Base64.getEncoder().encodeToString(this.plaintext);

	}
	
	@Override
	public String getString(Charset c) {
		return new String(this.plaintext, c);

	}

	@Override
	public boolean validateHash(AbstractSCCHash hash) {
		try {
			return scc.validateHash(this, hash);
		} catch (CoseException e) {
			e.printStackTrace();
			return false;
		}
	}


	@Override
	public boolean validatePasswordHash(AbstractSCCPasswordHash passwordHash) {
		try {
			return scc.validatePasswordHash(this, passwordHash);
		} catch (CoseException e) {
			e.printStackTrace();
			return false;
		}
	}


	@Override
	public SCCCiphertext symmetricEncrypt(AbstractSCCKey key, SecureCryptoConfig scc) {
		try {
			return scc.symmetricEncrypt(key, this);
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}


	@Override
	public SCCCiphertext asymmetricEncrypt(AbstractSCCKeyPair keyPair, SecureCryptoConfig scc) {
		try {
			return scc.asymmetricEncrypt(keyPair, this);
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}


	@Override
	public SCCSignature sign(AbstractSCCKeyPair keyPair, SecureCryptoConfig scc) {
		try {
			return scc.sign(keyPair, this);
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}


	@Override
	public SCCHash hash(SecureCryptoConfig scc) {
		try {
			return scc.hash(this);
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}


	@Override
	public SCCPasswordHash passwordHash(SecureCryptoConfig scc) {
		try {
			return scc.passwordHash(this);
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}


}
