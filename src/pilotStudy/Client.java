package pilotStudy;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.time.Instant;

import com.fasterxml.jackson.core.JsonProcessingException;

import COSE.CoseException;
import main.SCCKeyPair;
import main.SCCKeyPair.KeyPairUseCase;
import main.SecureCryptoConfig;

public class Client implements Runnable {

	int clientID;
	KeyPair pair;
	Server server;

	private Client(int clientID, KeyPair pair, Server server) {
		this.clientID = clientID;
		this.pair = pair;
		this.server = server;
	}

	public int getID() {
		return this.clientID;
	}

	private KeyPair getKeyPair() {
		return this.pair;
	}

	public static Client generateNewClient(Server server)
			throws NoSuchAlgorithmException, CoseException, IllegalStateException {

		SCCKeyPair pair = SCCKeyPair.createKeyPair(KeyPairUseCase.Signing);
		PublicKey publicKey = pair.getPublicKey();
		// TODO: create method sendPublicKey
		int clientID = server.registerClient(publicKey);
		if (clientID == -1) {
			throw new IllegalStateException("server does not seem to accept the client registration!");
		}

		Client c = new Client(clientID, pair.getKeyPair(), server);
		return c;
	}

	private static String generateOrder() throws NumberFormatException, JsonProcessingException {
		int random = (int) (100 * Math.random());
		if (random <= 50) {
			return Message.createBuyStockMessage(generateRandomString(12), generateRandomNumber(3));
		} else {
			return Message.createSellStockMessage(generateRandomString(12), generateRandomNumber(10));
		}

	}

	private static byte[] sign(String order, KeyPair pair) throws CoseException {
		SecureCryptoConfig scc = new SecureCryptoConfig();
		// SCCKeyPair sccPair = null;
		SCCKeyPair sccPair = new SCCKeyPair(pair);

		// SCCSignature sig = scc.sign(sccPair, order);
		return "todo signature".getBytes();// sig.toString();
	}

	private void sendOrder(String order) throws CoseException, JsonProcessingException {
		KeyPair pair = this.pair;

		String signedMessage = SignedMessage.createSignedMessage(this.clientID, order, sign(order, pair));

		// String signature = sign(order, pair);

		// String messageToServer = this.clientID + ";" + new String(order) + ";" +
		// signature;
		p("sending to server: " + signedMessage);
		String result = server.acceptMessage(signedMessage);
		p("result from server: " + result);

		// TODO: send signature, order and clientID to Server
	}

	private static String generateRandomNumber(int length) {

		String AlphaNumericString = "01234567890";
		StringBuilder sb = new StringBuilder(length);

		for (int i = 0; i < length; i++) {
			int index = (int) (AlphaNumericString.length() * Math.random());
			sb.append(AlphaNumericString.charAt(index));
		}

		return sb.toString();
	}

	private static String generateRandomString(int length) {

		String AlphaNumericString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
		StringBuilder sb = new StringBuilder(length);

		for (int i = 0; i < length; i++) {
			int index = (int) (AlphaNumericString.length() * Math.random());
			sb.append(AlphaNumericString.charAt(index));
		}

		return sb.toString();
	}

	private void p(String s) {
		System.out.println(Instant.now().toString() + " client " + this.clientID + ": " + s);
	}

	@Override
	public void run() {
		while (true) {
			try {
				Thread.sleep(500 + (long) (1000 * Math.random()));
				sendOrder(generateOrder());

				// p("sleeping");
				Thread.sleep(5000 + (long) (5000 * Math.random()));

			} catch (InterruptedException | CoseException e) {
				// TODO Auto-generated catch block
				// e.printStackTrace();
			} catch (NumberFormatException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (JsonProcessingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

	}
}
