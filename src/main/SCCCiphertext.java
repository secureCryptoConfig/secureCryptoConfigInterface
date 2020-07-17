package main;

import java.nio.charset.Charset;
import COSE.CoseException;

/**
 * Class represention the Ciphertext resulting from symetric/asymetric encryption.
 * @author Lisa
 *
 */
public class SCCCiphertext extends AbstractSCCCiphertext {

	private SecureCryptoConfig scc = new SecureCryptoConfig();
	
	/**
	 * Constructor that gets the byte[] representation of the COSE message resulting from encryption
	 * @param msg
	 */
	public SCCCiphertext(byte[] msg) {
		super(msg);
	}
	
	@Override
	public byte[] toBytes() {
		return this.msg;
	}
	
	@Override
	public String toString(Charset c) {
		return new String (this.msg, c);
	}
	

	@Override
	public PlaintextContainer decryptSymmetric(AbstractSCCKey key) {
		try {
			return scc.decryptSymmetric(key, this);
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

	@Override
	public PlaintextContainer decryptAsymmetric(AbstractSCCKey pair) {
		try {
			return scc.decryptAsymmetric(pair, this);
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

	@Override
	public SCCCiphertext reEncryptSymmetric(AbstractSCCKey key)  {
		try {
		return scc.reEncryptSymmetric(key, this);
		}catch(CoseException e)
		{
			e.printStackTrace();
			return null;
		}
	}

	@Override
	public SCCCiphertext reEncryptAsymmetric(AbstractSCCKey keyPair) {
		try {
			return scc.reEncryptAsymmetric(keyPair, this);
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}
	

}
