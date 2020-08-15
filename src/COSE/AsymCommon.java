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
        String algName;
        switch (alg) {
            case RSA_OAEP_SHA_512:
            	algName = "RSA/ECB/OAEPWithSHA-512AndMGF1Padding";
            	RSA_Decrypt(rgbKey, algName);
                break;
            case RSA_OAEP_SHA_256:
            	algName = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
            	RSA_Decrypt(rgbKey, algName);
            case RSA_PKCS1:
            	algName = "RSA/ECB/PKCS1Padding";
            	RSA_Decrypt(rgbKey, algName);
            default:
                throw new CoseException("Unsupported Algorithm Specified");
        }
        
        return rgbContent;
    }
    
    private void RSA_Decrypt(KeyPair rgbKey, String algName) {
    	try {
			Cipher cipher = Cipher.getInstance(algName);
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
        String algName;
        switch (alg) {
            case RSA_OAEP_SHA_512:
            	algName = "RSA/ECB/OAEPWithSHA-512AndMGF1Padding";
            	RSA_Encrypt(rgbKey, algName);
                break;
            case RSA_OAEP_SHA_256:
            	algName = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
            	RSA_Encrypt(rgbKey, algName);
            case RSA_PKCS1:
            	algName = "RSA/ECB/PKCS1Padding";
            	RSA_Encrypt(rgbKey, algName);
            default:
                throw new CoseException("Unsupported Algorithm Specified");
        }
        
        //ProcessCounterSignatures();
    }

	private void RSA_Encrypt(KeyPair rgbKey, String algName) {
		try {
			Cipher cipher = Cipher.getInstance(algName);
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
