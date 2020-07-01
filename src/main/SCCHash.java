package main;

import java.nio.charset.Charset;

import com.upokecenter.cbor.CBORObject;

import COSE.AlgorithmID;
import COSE.CoseException;
import COSE.HashMessage;
import COSE.HeaderKeys;

public class SCCHash extends AbstractSCCHash{

	SecureCryptoConfig scc = new SecureCryptoConfig();
	
	public SCCHash(PlaintextContainer plaintext, PlaintextContainer hash, byte[] hashMsg)
	{
		super(plaintext, hash, hashMsg);
	}
	
	@Override
	public boolean validateHash(PlaintextContainerInterface plain) {
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
	public AlgorithmID getAlgorithmIdentifier() {
		try {
		HashMessage msg = convertByteToMsg();
		CBORObject obj = msg.findAttribute(HeaderKeys.Algorithm);
		AlgorithmID alg = AlgorithmID.FromCBOR(obj);
		return alg;
		}catch(CoseException e)	
		{
			e.printStackTrace();
			return null;
		}
	}


	@Override
	public PlaintextContainer getHashAsPlaintextContainer() {
		return (PlaintextContainer) this.hash;
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

	@Override
	public SCCHash updateHash() {
		try {
			return scc.hash(this.plaintext);
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

	@Override
	public PlaintextContainerInterface getPlaintextAsPlaintextContainer() {
		return this.plaintext;
	}

	@Override
	public String getPlaintextAsString(Charset c) {
		return new String (this.plaintext.getPlaintextBytes(), c);
	}
	
	public String getHashAsString(Charset c)
	{
		return new String (this.hash.getPlaintextBytes(), c);
	}
	
	@Override
	public byte[] getHashBytes() {
		return this.hash.getPlaintextBytes();
	}
}
