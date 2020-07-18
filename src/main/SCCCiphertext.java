package main;

import java.nio.charset.Charset;
import java.security.InvalidKeyException;

import COSE.CoseException;

/**
 * Class represention the ciphertext resulting from symmetric/asymmetric encryption.
 * SCCCiphertext includes a byte[] representation of a COSE message. The byte[] contains the encrypted plaintext as well as all the parameters used during encryption. 
 * In this way it is possible to decrypt the SCCCiphertext with the right choice of parameters easily.
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
	public PlaintextContainer decryptSymmetric(AbstractSCCKey key) throws SCCException {
		try {
			return scc.decryptSymmetric(key, this);
		} catch (CoseException e) {
			throw new SCCException("Symmetric decryption could not be performed!", e);
		}catch(InvalidKeyException e)
		{
			throw new SCCException("Symmetric decryption is not possible! Not the right KeyType!", e);
		}
	}

	@Override
	public PlaintextContainer decryptAsymmetric(AbstractSCCKey pair) throws SCCException {
		try {
			return scc.decryptAsymmetric(pair, this);
		} catch (CoseException e) {
			throw new SCCException("Asymmetric decryption could not be performed!", e);
		}catch(InvalidKeyException e)
		{
			throw new SCCException("Asymmetric decryption is not possible! Not the right KeyType!", e);
		}
	}

	@Override
	public SCCCiphertext reEncryptSymmetric(AbstractSCCKey key) throws SCCException  {
		try {
		return scc.reEncryptSymmetric(key, this);
		} catch (CoseException e) {
			throw new SCCException("Symmetric ReEncryption could not be performed!", e);
		}catch(InvalidKeyException e)
		{
			throw new SCCException("Symmetric ReEncryption is not possible! Not the right KeyType!", e);
		}
	}

	@Override
	public SCCCiphertext reEncryptAsymmetric(AbstractSCCKey keyPair) throws SCCException {
		try {
			return scc.reEncryptAsymmetric(keyPair, this);
		} catch (CoseException e) {
			throw new SCCException("Asymmetric ReEncryption could not be performed!", e);
		}catch(InvalidKeyException e)
		{
			throw new SCCException("Asymmetric ReEncryption is not possible! Not the right KeyType!", e);
		}
	}
	

}
