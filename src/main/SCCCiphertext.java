package main;

import java.nio.charset.Charset;
import com.upokecenter.cbor.CBORObject;

import COSE.AlgorithmID;
import COSE.CoseException;
import COSE.HeaderKeys;
import COSE.Message;

public class SCCCiphertext extends AbstractSCCCiphertext {

	SecureCryptoConfig scc = new SecureCryptoConfig();
	
	public SCCCiphertext(PlaintextContainerInterface plaintext, byte[] cipher, byte[] msg) {
		super(plaintext, cipher, msg);
	}
	
	@Override
	public byte[] getMessageBytes() {
		return this.msg;
	}

	@Override
	public AlgorithmID getAlgorithmIdentifier() {
		try {
		Message msg = convertByteToMsg();
		CBORObject obj = msg.findAttribute(HeaderKeys.Algorithm);
		AlgorithmID alg = AlgorithmID.FromCBOR(obj);
		return alg;
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	
	}

	@Override
	public byte[] getCipherBytes() {
		return this.cipher;
	}
	
	@Override
	public String getCipherAsString(Charset c) {
		return new String (this.cipher, c);
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
	public PlaintextContainer getPlaintextAsPlaintextContainer() {
		return (PlaintextContainer) this.plain;
	}
	
	@Override
	public String getPlaintextAsString(Charset c) {
		return new String (this.plain.getByteArray(), c);
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
	public SCCCiphertext symmetricReEncrypt(AbstractSCCKey key)  {
		try {
		return scc.symmetricReEncrypt(key, this);
		}catch(CoseException e)
		{
			e.printStackTrace();
			return null;
		}
	}

	@Override
	public SCCCiphertext asymmetricReEncrypt(AbstractSCCKeyPair keyPair) {
		try {
			return scc.asymmetricReEncrypt(keyPair, this);
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

}
