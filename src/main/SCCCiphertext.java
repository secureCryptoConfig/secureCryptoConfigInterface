package main;

import com.upokecenter.cbor.CBORObject;

import COSE.AlgorithmID;
import COSE.CoseException;
import COSE.HeaderKeys;
import COSE.Message;

public class SCCCiphertext extends AbstractSCCCiphertext {

	SecureCryptoConfig scc = new SecureCryptoConfig();
	
	// for COSE
	public SCCCiphertext(PlaintextContainerInterface plaintext, byte[] cipher, AbstractSCCKey key, byte[] msg) {
		super(plaintext, cipher, key, msg);
	}
	
	public SCCCiphertext(PlaintextContainerInterface plain, byte[] cipher, AbstractSCCKeyPair keyPair, byte[] msg) {
		super(plain, cipher, keyPair, msg);
	}

	@Override
	public byte[] getMessageBytes() {
		return this.msg;
	}

	@Override
	public AlgorithmID getAlgorithmIdentifier() throws CoseException {
		Message msg = convertByteToMsg();
		CBORObject obj = msg.findAttribute(HeaderKeys.Algorithm);
		AlgorithmID alg = AlgorithmID.FromCBOR(obj);
		return alg;
	}

	@Override
	public byte[] getCipherBytes() {
		return this.cipher;
	}

	@Override
	public Message convertByteToMsg() {
		try {
			return (Message) Message.DecodeFromBytes(this.msg);
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

	@Override
	public PlaintextContainer getPlain() {
		return (PlaintextContainer) this.plain;
	}


	@Override
	public PlaintextContainer symmetricDecrypt(AbstractSCCKey key) {
		try {
			return scc.symmetricDecrypt(key, this);
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

	@Override
	public PlaintextContainer asymmetricDecrypt(AbstractSCCKeyPair keyPair) {
		try {
			return scc.asymmetricDecrypt(keyPair, this);
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

	@Override
	public SCCCiphertext symmetricReEncrypt(AbstractSCCKey key, SecureCryptoConfig scc) throws CoseException  {
		return scc.symmetricReEncrypt(key, this);
	}

	@Override
	public SCCCiphertext asymmetricReEncrypt(AbstractSCCKeyPair keyPair, SecureCryptoConfig scc) throws CoseException {
		return scc.asymmetricReEncrypt(keyPair, this);
	}

}
