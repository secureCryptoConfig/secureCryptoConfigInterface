package main;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.URISyntaxException;
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

/**
 * Class for handling/parsing SCC file content
 * 
 * @author Lisa
 *
 */
public class JSONReader {
	
	private static ArrayList<String> allFilePaths = new ArrayList<String>();
	protected static HashMap<String, Integer> levelsNames = new HashMap<String, Integer>();
	protected static HashSet<Integer> levels = new HashSet<Integer>();

	// JSON parser object to parse read file
	private static JSONParser jsonParser = new JSONParser();

	// Enum representing supported crypto use cases
	protected enum CryptoUseCase {
		SymmetricEncryption, Signing, Hashing, AsymmetricEncryption, PasswordHashing, KeyGeneration;
	}
	
	

	/**
	 * retrieving Algorithms for specific Crypto Use case out of JSON
	 * 
	 * @param useCase, value from Enum
	 */
	protected static ArrayList<String> getAlgos(CryptoUseCase useCase, String sccFilePath) {
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
	 * Auxiliary method for reading out theversion of a file at given path
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
	 * @param path to root directory "config"
	 */
	protected static void getFiles(String path) {

		File folder = new File(path);
		File[] listOfFiles = folder.listFiles();
		for (int i = 0; i < listOfFiles.length; i++) {

			if (listOfFiles[i].isFile()) {
				allFilePaths.add(path + "\\" + listOfFiles[i].getName());

			} else {
				getFiles(path + "\\" + listOfFiles[i].getName());
			}
		}

	}

	/**
	 * Determine Security Level number for a specific SCC file (file:level)
	 */
	protected static void getSecurityLevel() {
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
	 * @param Set with all appearing Security Level numbers
	 * @return highest appearing level
	 */
	protected static int getHighestLevel(HashSet<Integer> level) {
		return Collections.max(level);
	}

	/**
	 * 
	 * @param path to "configs" folder containing SCC files
	 * @return path to latest SCC file with highest appearing Security Level number
	 */
	protected static String parseFiles(String path) {
		allFilePaths.clear();
		getFiles(path);
		getSecurityLevel();
		return getLatestSCC(getHighestLevel(levels));
	}

}
