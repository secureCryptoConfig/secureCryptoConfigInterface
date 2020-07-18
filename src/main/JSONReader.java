package main;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import main.SCCKey.KeyType;

/**
 * Class for handling/parsing SCC file content
 * 
 * @author Lisa
 *
 */
public class JSONReader {

	private static ArrayList<String> allFilePaths = new ArrayList<String>();
	private static HashMap<String, Integer> levelsNames = new HashMap<String, Integer>();
	protected static HashSet<Integer> levels = new HashSet<Integer>();

	private static String publicKeyPath1;
	private static String publicKeyPath2;
	private static String signatureAlgo = "EC";

	// JSON parser object to parse read file
	private static JSONParser jsonParser = new JSONParser();

	// Enum representing supported crypto use cases
	protected enum CryptoUseCase {
		SymmetricEncryption, Signing, Hashing, AsymmetricEncryption, PasswordHashing, KeyGeneration;
	}

	/**
	 * Retrieving algorithms for specific Crypto Use case out of JSON
	 * 
	 * @param useCase, sccFilePath (Path to used SCC file)
	 */
	protected static ArrayList<String> getAlgos(CryptoUseCase useCase, String sccFilePath) {
		JSONParser jsonParser = new JSONParser();
		ArrayList<String> algos = new ArrayList<String>();
		try (FileReader reader = new FileReader(sccFilePath)) {
			// Read JSON file
			Object obj = jsonParser.parse(reader);
			JSONArray sccList = (JSONArray) obj;
			JSONObject scc = (JSONObject) sccList.get(0);

			JSONObject usageObject = (JSONObject) scc.get("Usage");
			JSONArray use = (JSONArray) usageObject.get(useCase.toString());
			Iterator<?> iterator = use.iterator();
			while (iterator.hasNext()) {
				// System.out.println(iterator.next());
				algos.add((String) iterator.next());
			}
			return algos;
		} catch (IOException | ParseException e) {
			e.printStackTrace();
			return null;
		}

	}

	/**
	 * Auxiliary method for reading out the version of a file at given path
	 * 
	 * @param path to file
	 */
	private static String getVersion(String sccFilePath) {
		String result = "";
		try {
			FileReader reader = new FileReader(sccFilePath);
			// Read JSON file
			Object obj = jsonParser.parse(reader);
			JSONArray sccList = (JSONArray) obj;
			JSONObject scc = (JSONObject) sccList.get(0);

			result = (String) scc.get("Version");

			return result;
		} catch (IOException | ParseException e) {
			e.printStackTrace();
			return null;
		}

	}

	/**
	 * Auxiliary method for reading out the Security Level of a file at given path
	 * 
	 * @param path to file
	 */
	private static String getSecurityLevel(String sccFilePath) {
		String result = "";
		try {
			FileReader reader = new FileReader(sccFilePath);
			// Read JSON file
			Object obj = jsonParser.parse(reader);
			JSONArray sccList = (JSONArray) obj;
			JSONObject scc = (JSONObject) sccList.get(0);

			result = (String) scc.get("SecurityLevel");
			return result;
		} catch (IOException | ParseException e) {
			e.printStackTrace();
			return null;
		}

	}

	/**
	 * Returns the path to default SCC files in directory src/configs
	 * 
	 * @return
	 */
	protected static String getBasePath() {
		String basePath = "";
		try {
			basePath = new File(JSONReader.class.getProtectionDomain().getCodeSource().getLocation().toURI()).getPath()
					.replace("\\target\\classes", "");
		} catch (URISyntaxException e) {
			e.printStackTrace();
		}
		return basePath = basePath + "\\src\\scc-configs\\";
	}

	/**
	 * Get all files out of root "configs" directory of given path
	 * 
	 * @param path to root directory "config"
	 */
	private static void getFiles(String path) {
		try {
			Files.walk(Paths.get(path)).filter(Files::isRegularFile)
					.filter(file -> file.getFileName().toString().endsWith(".json")).forEach(file -> {
						allFilePaths.add(file.toString());

					});
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	/**
	 * Determine Security Level number for a specific SCC file (file:level)
	 */
	private static void getSecurityLevel() {
		int level;
		levels.clear();
		levelsNames.clear();
		for (int i = 0; i < allFilePaths.size(); i++) {
			level = Integer.parseInt(getSecurityLevel(allFilePaths.get(i)));
			levelsNames.put(allFilePaths.get(i), level);
			levels.add(level);
		}
	}

	/**
	 * Determines path to latest SCC file with given Security level
	 * 
	 * @param level
	 * @return path to latest SCC file with given Security level
	 */
	protected static String getLatestSCC(int level) {
		String latest = null;
		ArrayList<String> pathsWithKey = new ArrayList<String>();
		HashMap<String, String> pathVersion = new HashMap<String, String>();

		if (levels.contains(level)) {
			// which file have security level
			for (HashMap.Entry<String, Integer> entry : levelsNames.entrySet()) {
				if (entry.getValue().equals(level)) {
					pathsWithKey.add(entry.getKey());
				}
			}

			for (int i = 0; i < pathsWithKey.size(); i++) {
				String version = getVersion(pathsWithKey.get(i));
				pathVersion.put(pathsWithKey.get(i), version);
			}

			int highestYear = 0;
			int highestPatch = 0;

			Set<String> keys = pathVersion.keySet();
			for (String s : keys) {
				String nmb = pathVersion.get(s);
				String version[] = nmb.split("-");
				Integer versionInt[] = new Integer[2];
				versionInt[0] = Integer.parseInt(version[0]);
				versionInt[1] = Integer.parseInt(version[1]);
				if (highestYear < versionInt[0]) {
					latest = s;
					highestYear = versionInt[0];

				} else if (highestYear == versionInt[0]) {
					if (highestPatch < versionInt[1]) {
						highestPatch = versionInt[1];
						latest = s;
					}
				}
			}
			return latest;
		} else {
			throw new IllegalArgumentException("No file for the specified Security Level Number");
		}

	}

	/**
	 * Determines the highest Security Level number in Set
	 * 
	 * @param Set with all appearing Security Level numbers
	 * @return highest appearing level
	 */
	protected static int getHighestLevel(HashSet<Integer> level) {
		return Collections.max(level);
	}

	private static boolean checkSignature(String algo, String signaturePath, String publicKeyPath) throws IOException,
			NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {

		Path fileLocation = Paths.get(publicKeyPath);
		byte[] publicKey = Files.readAllBytes(fileLocation);
		PublicKey pub = KeyFactory.getInstance(algo.toString()).generatePublic(new X509EncodedKeySpec(publicKey));

		SCCKey sccKeyPair = new SCCKey(KeyType.Asymmetric, pub.getEncoded(), null, algo);

		Path fileLocation1 = Paths.get(signaturePath);
		byte[] sig = Files.readAllBytes(fileLocation1);

		SCCSignature signature = new SCCSignature(sig);
		return signature.validateSignature(sccKeyPair);

	}

	private static void getPublicKeyPath() {

		File folder = new File(getBasePath() + "publicKeys\\");
		File[] listOfFiles = folder.listFiles();
		publicKeyPath1 = getBasePath() + "publicKeys\\" + listOfFiles[0].getName();
		publicKeyPath2 = getBasePath() + "publicKeys\\" + listOfFiles[1].getName();

	}

	private static void startValidation() {
		for (int i = 0; i < allFilePaths.size(); i++) {
			String filepath = allFilePaths.get(i);
			String signaturePath1 = filepath;
			String signaturePath2 = filepath;
			String[] parts = allFilePaths.get(i).split("\\\\");
			String signatureFileName1 = parts[parts.length - 1].replace(".json", "-signature1");
			String signatureFileName2 = parts[parts.length - 1].replace(".json", "-signature2");
			signaturePath1 = filepath.replace(parts[parts.length - 1], "") + signatureFileName1;
			signaturePath2 = filepath.replace(parts[parts.length - 1], "") + signatureFileName2;

			boolean validation1 = false;
			boolean validation2 = false;

			if (new File(signaturePath1).exists() && new File(signaturePath2).exists()) {

				try {
					validation1 = checkSignature(signatureAlgo, signaturePath1, publicKeyPath1);
					validation2 = checkSignature(signatureAlgo, signaturePath2, publicKeyPath2);
				} catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | SignatureException
						| IOException e) {
					e.printStackTrace();
				}
				if (validation1 != true || validation2 != true) {
					System.out.println("Not both signatures are valid for " + filepath);
					System.out.println("This file will not be considered!");
					allFilePaths.remove(i);
				}
			} else {
				System.out.println("There are no two signatures defined for " + filepath);
				System.out.println("This file will not be considered!");
				allFilePaths.remove(i);
			}

		}
	}

	/**
	 * Determine path to latest SCC file with highest appearing Security Level
	 * number
	 * 
	 * @param path to "configs" folder containing SCC files
	 * @return path
	 */
	protected static String parseFiles(String path) {
		allFilePaths.clear();
		getFiles(path);
		if (SecureCryptoConfig.customPath == true) {
			getPublicKeyPath();
			startValidation();
		}
		getSecurityLevel();
		return getLatestSCC(getHighestLevel(levels));
	}

}
