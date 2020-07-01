package main;

import java.nio.charset.Charset;

import com.upokecenter.cbor.CBORObject;

import COSE.AlgorithmID;
import COSE.CoseException;
import COSE.HeaderKeys;
import COSE.PasswordHashMessage;

public class SCCPasswordHash extends AbstractSCCPasswordHash {

	public SCCPasswordHash(PlaintextContainer password, PlaintextContainer hash, byte[] hashMsg) {
		super(password, hash, hashMsg);
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
	public byte[] getMessageBytes() {
		return this.hashMsg;
	}

	@Override
	public AlgorithmID getAlgorithmIdentifier() {
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

	@Override
	public PlaintextContainer getHashAsPlaintextContainer() {
		return (PlaintextContainer) this.hash;
	}

	@Override
	public PasswordHashMessage convertByteToMsg() {
		try {
			return (PasswordHashMessage) PasswordHashMessage.DecodeFromBytes(this.hashMsg);
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
		return new String(this.plaintext.getPlaintextBytes(), c);
	}

	@Override
	public String getHashAsString(Charset c) {
		return new String(this.hash.getPlaintextBytes(), c);
	}

	@Override
	public byte[] getHashBytes() {
		return this.hash.getPlaintextBytes();
	}
}
