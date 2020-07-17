package pilotStudy;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

@JsonAutoDetect(fieldVisibility = Visibility.ANY)
public class SignedMessage {

	private int clientId;

	public int getClientId() {
		return clientId;
	}

	public void setClientId(int clientId) {
		this.clientId = clientId;
	}

	private String content;

	public String getContent() {
		return content;
	}

	public void setContent(String content) {
		this.content = content;
	}

	public byte[] getSignature() {
		return signature;
	}

	public void setSignature(byte[] signature) {
		this.signature = signature;
	}

	private byte[] signature;

	private SignedMessage(int clientId, String content, byte[] signature) {
		setClientId(clientId);
		this.content = content;
		this.signature = signature;
	}

	public SignedMessage() {

	}

	public static String createSignedMessage(int clientId, String message, byte[] signature)
			throws JsonProcessingException {
		ObjectMapper mapper = new ObjectMapper();

		return mapper.writeValueAsString(new SignedMessage(clientId, message, signature));
	}

}
