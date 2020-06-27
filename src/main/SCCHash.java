package main;

import java.util.Base64;

import com.upokecenter.cbor.CBORObject;

import COSE.CoseException;
import COSE.HashMessage;
import COSE.HeaderKeys;

public class SCCHash extends AbstractSCCHash{

	SecureCryptoConfig scc = new SecureCryptoConfig();
	byte[] hashMsg;
	
	public SCCHash(byte[] hashMsg)
	{
		this.hashMsg = hashMsg;
	}
	
	@Override
	public boolean verifyHash(PlaintextContainer plain) {
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
	public CBORObject getAlgorithmIdentifier() {
		HashMessage msg = convertByteToMsg();
		CBORObject obj = msg.findAttribute(HeaderKeys.Algorithm);
		return obj;
	}

	@Override
	public String getPlain() {
		HashMessage m = convertByteToMsg();
		return Base64.getEncoder().encodeToString(m.GetContent());
	}

	@Override
	public PlaintextContainer getHashedContent() {
		try {
			HashMessage m = convertByteToMsg();
			return new PlaintextContainer(m.getHashedContent());

		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
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
