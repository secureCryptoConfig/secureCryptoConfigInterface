package main;

import com.upokecenter.cbor.CBORObject;

import COSE.AlgorithmID;
import COSE.CoseException;
import COSE.HashMessage;
import COSE.HeaderKeys;

public class SCCHash extends AbstractSCCHash{

	SecureCryptoConfig scc = new SecureCryptoConfig();
	public byte[] hashMsg;
	PlaintextContainer plaintext, hash;
	
	public SCCHash(PlaintextContainer plaintext, PlaintextContainer hash, byte[] hashMsg)
	{
		this.hashMsg = hashMsg;
		this.hash = hash;
		this.plaintext = plaintext;
	}
	
	@Override
	public boolean validateHash(PlaintextContainer plain) {
		try {
			return scc.validateHash(plain, this);
		} catch (CoseException e) {
			e.printStackTrace();
			return false;
		}
	}

	@Override
	public byte[] getMessageBytes() {
		return this.hashMsg;
	}

	@Override
	public AlgorithmID getAlgorithmIdentifier() throws CoseException {
		HashMessage msg = convertByteToMsg();
		CBORObject obj = msg.findAttribute(HeaderKeys.Algorithm);
		AlgorithmID alg = AlgorithmID.FromCBOR(obj);
		return alg;
	}

	@Override
	public PlaintextContainerInterface getPlain() {
		return this.plaintext;
	}

	@Override
	public PlaintextContainer getHashedContent() {
		return this.hash;
	}

	@Override
	public HashMessage convertByteToMsg() {
		try {
			return (HashMessage) HashMessage.DecodeFromBytes(this.hashMsg);
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}
}
