package COSE;

import java.security.KeyPair;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

public class AsymMessage extends AsymCommon {

	/**
	 * Create a AsymMessage object. This object corresponds to the encrypt
	 * message format in COSE. The leading CBOR tag will be emitted. The message
	 * content will be emitted.
	 */
	public AsymMessage() {
		this(true, true);
	}

	/**
	 * Create a AsymMessage object. This object corresponds to the encrypt
	 * message format in COSE.
	 * 
	 * @param emitTag     is the leading CBOR tag emitted
	 * @param emitContent is the content emitted
	 */
	public AsymMessage(boolean emitTag, boolean emitContent) {
		context = "Asym";
		messageTag = MessageTag.Asym;
		this.emitTag = emitTag;
		this.emitContent = emitContent;
	}

	@Override
	public void DecodeFromCBORObject(CBORObject obj) throws CoseException {
		if (obj.size() != 3)
			throw new CoseException("Invalid Asymmetric structure");

		if (obj.get(0).getType() == CBORType.ByteString) {
			if (obj.get(0).GetByteString().length == 0) {
				rgbProtected = new byte[0];
				objProtected = CBORObject.NewMap();
			} else {
				rgbProtected = obj.get(0).GetByteString();
				objProtected = CBORObject.DecodeFromBytes(rgbProtected);
				if (objProtected.getType() != CBORType.Map)
					throw new CoseException("Invalid Asym structure");
			}

		} else
			throw new CoseException("Invalid Asymmetric structure");

		if (obj.get(1).getType() == CBORType.Map)
			objUnprotected = obj.get(1);
		else
			throw new CoseException("Invalid Asymmetric structure");

		if (obj.get(2).getType() == CBORType.ByteString)
			rgbEncrypt = obj.get(2).GetByteString();
		else if (!obj.get(2).isNull())
			throw new CoseException("Invalid Asymmetric structure");

	}

	/**
	 * Internal function used to construct the CBORObject
	 * 
	 * @return the constructed CBORObject
	 * @throws CoseException if the content has not yet been encrypted
	 */
	@Override
	protected CBORObject EncodeCBORObject() throws CoseException {
		if (rgbEncrypt == null)
			throw new CoseException("Encrypt function not called");

		CBORObject obj = CBORObject.NewArray();
		if (objProtected.size() > 0)
			obj.Add(objProtected.EncodeToBytes());
		else
			obj.Add(CBORObject.FromObject(new byte[0]));

		obj.Add(objUnprotected);

		if (emitContent)
			obj.Add(rgbEncrypt);
		else
			obj.Add(CBORObject.Null);

		return obj;
	}

	/**
	 * Decrypt the message using the passed in key.
	 * 
	 * @param rgbKey key for decryption
	 * @return the decrypted content
	 * @throws CoseException - Error during decryption
	 */
	public byte[] decrypt(KeyPair rgbKey) throws CoseException {
		return super.decryptWithKey(rgbKey);
	}

	/**
	 * Encrypt the message using the passed in key.
	 * 
	 * @param rgbKey key used for encryption
	 * @throws CoseException         - Error during decryption
	 * @throws IllegalStateException - Error during decryption
	 */
	public void encrypt(KeyPair rgbKey) throws CoseException, IllegalStateException {
		super.encryptWithKey(rgbKey);
	}
}
