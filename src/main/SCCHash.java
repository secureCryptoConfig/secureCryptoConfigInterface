package main;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import com.upokecenter.cbor.CBORObject;

import COSE.AlgorithmID;
import COSE.CoseException;
import COSE.HashMessage;
import COSE.HeaderKeys;

public class SCCHash extends AbstractSCCHash{

	SecureCryptoConfig scc = new SecureCryptoConfig();
	
	public SCCHash(PlaintextContainer plaintext, byte[] hashMsg)
	{
		super(plaintext, hashMsg);
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
	public byte[] toBytes() {
		return this.hashMsg;
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
	public String toString(Charset c) {
		return new String(this.hashMsg, c);
	}
	
	
	protected HashMessage convertByteToMsg() {
		try {
			return (HashMessage) HashMessage.DecodeFromBytes(this.hashMsg);
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

	/*
	
	protected AlgorithmID getAlgorithmIdentifier() {
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


	
	protected PlaintextContainer getHashAsPlaintextContainer() {
		return (PlaintextContainer) this.hash;
	}



	protected PlaintextContainerInterface getPlaintextAsPlaintextContainer() {
		return this.plaintext;
	}

	
	protected String getPlaintextAsString(Charset c) {
		return new String (this.plaintext.toBytes(), c);
	}
	
	protected String getHashAsString(Charset c)
	{
		return new String (this.hash.toBytes(), c);
	}
	
	
	protected byte[] getHashBytes() {
		return this.hash.toBytes();
	}
	*/
}
