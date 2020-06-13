package main;

import java.util.Base64;

public class SCCPasswordHash extends AbstractSCCPasswordHash {

	byte[] hash;
	SCCAlgorithmParameters param;

	public SCCPasswordHash(byte[] hash, SCCAlgorithmParameters param) {
		this.hash = hash;
		this.param = param;
	}

	@Override
	boolean verify(PlaintextContainer plaintext) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public String toString() {
		return Base64.getEncoder().encodeToString(this.hash);
	}
	
	@Override
	public String getAlgo()
	{
		return this.param.algo;
	}
	
	@Override
	public byte[] getSalt()
	{
		return this.param.salt;
	}
	
	@Override
	public int getKeySize()
	{
		return this.param.keysize;
	}

	@Override
	public int getIterations()
	{
		return this.param.iterations;
	}
}
