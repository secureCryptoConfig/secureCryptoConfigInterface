package main;

import java.io.ByteArrayOutputStream;
import java.util.Base64;

public class SCCCiphertextOutputStream extends AbstractSCCCiphertextOutputStream{

ByteArrayOutputStream byteArrayOutputStream;
	
	public SCCCiphertextOutputStream(ByteArrayOutputStream byteArrayOutputStream) {
		this.byteArrayOutputStream = byteArrayOutputStream;
	}
	
	@Override
	public ByteArrayOutputStream getStream()
	{
		return this.byteArrayOutputStream;
	}
	
	@Override
	public String getEncryptedContent()
	{
		return Base64.getEncoder().encodeToString(byteArrayOutputStream.toByteArray());
		
	}
	
	@Override
	public byte[] getEncryptedBytes()
	{
		return byteArrayOutputStream.toByteArray();
	}

}
