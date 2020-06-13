package main;

import java.util.Base64;

import COSE.Encrypt0Message;

public class SCCCiphertext extends AbstractSCCCiphertext {

	public SCCCiphertext(byte[] ciphertext, Encrypt0Message msg) {
		super(ciphertext, msg);
	}
	
	public SCCCiphertext(byte[] ciphertext, AbstractSCCAlgorithmParameters parameters) {
		super(ciphertext, parameters);
	}
	
	@Override 
	public String getCiphertext()
	{
		return Base64.getEncoder().encodeToString(this.ciphertext);
	}
	
	@Override 
	public byte[] getCipherBytes()
	{
		return this.ciphertext;
	}

	
	/**
	private SCCCiphertext generateSCCCiphertext() {
		//return SCCCiphertext(new String("empty").getBytes(), new SCCAlgorithmParameters());
		SCCCiphertext c = new SCCCiphertext(new String("empty").getBytes(), new SCCAlgorithmParameters(null, 0, null));
		return c;
	}
	**/
	/**
	public static SCCCiphertext getSCCCiphertext() {
		//return new SCCCiphertext();
		SCCCiphertext c = new SCCCiphertext(new String("empty").getBytes(), new SCCAlgorithmParameters(null, 0, null));
		return c;
	}
**/
	/**
	public SCCCiphertext sCCCiphertext(byte[] ciphertext, SCCAlgorithmParameters parameters) {
		this.ciphertext = ciphertext;
		this.parameters = parameters;
		return this;
	}
	**/

	@Override
	public String toString() {
		return Base64.getEncoder().encodeToString(this.ciphertext);
	}

	/**
	@Override
	public CBORObject getAlgorithmIdentifier() {
		Encrypt0Message m = this.msg;
		return m.getProtectedAttributes();
	}
	**/

}
