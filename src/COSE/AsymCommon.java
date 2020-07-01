package COSE;


import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;



import com.upokecenter.cbor.CBORObject;



public abstract class AsymCommon extends Message {

	
	protected String context;
    protected byte[] rgbEncrypt;
    SecureRandom random = new SecureRandom();
    
    protected byte[] decryptWithKey(KeyPair rgbKey) throws CoseException {
        CBORObject algX = findAttribute(HeaderKeys.Algorithm);
        AlgorithmID alg = AlgorithmID.FromCBOR(algX);
                
        if (rgbEncrypt == null) throw new CoseException("No Encrypted Content Specified");
 
        switch (alg) {
            case RSA_OAEP_SHA_512:
            	RSA_OAEP_SHA_512_Decrypt(rgbKey);
                break;
                
          
            default:
                throw new CoseException("Unsupported Algorithm Specified");
        }
        
        return rgbContent;
    }
    
    private void RSA_OAEP_SHA_512_Decrypt(KeyPair rgbKey) {
    	try {
			Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-512AndMGF1Padding");
			cipher.init(Cipher.DECRYPT_MODE, rgbKey.getPrivate());
			
	        rgbContent = cipher.doFinal(rgbEncrypt);
			
		} catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException | NoSuchAlgorithmException
				| NoSuchPaddingException e) {
			e.printStackTrace();
		}

	}

	void encryptWithKey(KeyPair rgbKey) throws CoseException, IllegalStateException {
        CBORObject algX = findAttribute(HeaderKeys.Algorithm);
        AlgorithmID alg = AlgorithmID.FromCBOR(algX);
                
        if (rgbContent == null) throw new CoseException("No Content Specified");

        switch (alg) {
            case RSA_OAEP_SHA_512:
            	RSA_OAEP_SHA_512_Encrypt(rgbKey);
                break;

           
            default:
                throw new CoseException("Unsupported Algorithm Specified");
        }
        
        //ProcessCounterSignatures();
    }

	private void RSA_OAEP_SHA_512_Encrypt(KeyPair rgbKey) {
		try {
			Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-512AndMGF1Padding");
			cipher.init(Cipher.ENCRYPT_MODE, rgbKey.getPublic());
            rgbEncrypt = cipher.doFinal(rgbContent);
			
		} catch (IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException
				| InvalidKeyException e) {
			e.printStackTrace();
		}
		
	}
	
	public byte[] getEncryptedContent() throws CoseException{
        if (rgbEncrypt == null) throw new CoseException("No Encrypted Content Specified");
        
        return rgbEncrypt;
    }
    
  
}
