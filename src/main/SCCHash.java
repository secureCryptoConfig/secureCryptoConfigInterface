package main;

import java.util.Base64;

public class SCCHash extends AbstractSCCHash{

	byte[] hash;
	SCCAlgorithmParameters param;
	
	public SCCHash(byte[] hash, SCCAlgorithmParameters param)
	{
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
}
