package main;

import java.nio.charset.Charset;

import com.upokecenter.cbor.CBORObject;

import COSE.AlgorithmID;
import COSE.CoseException;
import COSE.HeaderKeys;
import COSE.PasswordHashMessage;

public class SCCPasswordHash extends AbstractSCCPasswordHash {
	
	SecureCryptoConfig scc = new SecureCryptoConfig();

	public SCCPasswordHash(PlaintextContainer password, PlaintextContainer hash, byte[] hashMsg) {
		super(password, hashMsg);
	}

	@Override
	public boolean validatePasswordHash(PlaintextContainerInterface password) {
		try {
			return scc.validatePasswordHash(password, this);
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
	public String toString(Charset c) {
		return new String(this.hashMsg, c);
	}
	
	protected PasswordHashMessage convertByteToMsg() {
		try {
			return (PasswordHashMessage) PasswordHashMessage.DecodeFromBytes(this.hashMsg);
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

	/*
	protected byte[] getMessageBytes() {
		return this.hashMsg;
	}

	protected AlgorithmID getAlgorithmIdentifier() {
		try {
			PasswordHashMessage msg = convertByteToMsg();
			CBORObject obj = msg.findAttribute(HeaderKeys.Algorithm);
			AlgorithmID alg = AlgorithmID.FromCBOR(obj);
			return alg;
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

	protected PlaintextContainer getHashAsPlaintextContainer() {
		return (PlaintextContainer) this.hash;
	}


	public PlaintextContainerInterface getPlaintextAsPlaintextContainer() {
		return this.plaintext;
	}

	public String getPlaintextAsString(Charset c) {
		return new String(this.plaintext.toBytes(), c);
	}

	public String getHashAsString(Charset c) {
		return new String(this.hash.toBytes(), c);
	}

	public byte[] getHashBytes() {
		return this.hash.toBytes();
	}
	*/
}
