package pilotStudy;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.time.Instant;

import COSE.CoseException;
import main.SCCKeyPair;
import main.SCCKeyPair.KeyPairUseCase;
import main.SecureCryptoConfig;

public class Client implements Runnable {

	int clientID;
	KeyPair pair;
	Server server;

	enum TransactionType {
		Buy, Sell
	}

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

	private static byte[] generateOrder(TransactionType type) {

		String ISIN = generateRandomNumber(4);
		String amount = generateRandomNumber(3);
		String order = type.toString() + ";" + ISIN + ";" + amount;
		return order.getBytes();
	}

	private static String sign(byte[] order, KeyPair pair) throws CoseException {
		SecureCryptoConfig scc = new SecureCryptoConfig();
		// SCCKeyPair sccPair = null;
		SCCKeyPair sccPair = new SCCKeyPair(pair);

		// SCCSignature sig = scc.sign(sccPair, order);
		return "todo signature";// sig.toString();
	}

	private void sendOrder(byte[] order) throws CoseException {
		KeyPair pair = this.pair;
		String signature = sign(order, pair);

		String messageToServer = this.clientID + ";" + new String(order) + ";" + signature;
		p("sending to server: " + messageToServer);
		int result = server.acceptMessage(messageToServer);
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

	private void p(String s) {
		System.out.println(Instant.now().toString() + " client " + this.clientID + ": " + s);
	}

	@Override
	public void run() {
		while (true) {
			try {
				Thread.sleep(500 + (long) (1000 * Math.random()));
				sendOrder(generateOrder(TransactionType.Buy));

				// p("sleeping");
				Thread.sleep(5000 + (long) (5000 * Math.random()));

			} catch (InterruptedException | CoseException e) {
				// TODO Auto-generated catch block
				// e.printStackTrace();
			}
		}

	}
}
