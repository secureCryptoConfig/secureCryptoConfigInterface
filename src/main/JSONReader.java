package main;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;


public class JSONReader {

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
	 * Auxiliary method for readJSON method Prints all names/URL from each publisher
	 * 
	 * @param publisher
	 */
	private static void getPublisher(JSONObject publisher) {

		// Get publisher name
		String name = (String) publisher.get("name");
		System.out.println(name);

		String url = (String) publisher.get("URL");
		System.out.println(url);

	}

	/**
	 * Auxiliary method for readJSON method Prints all algorithms for a given
	 * useCase
	 * 
	 */

	private static void getUsage(CryptoUseCase useCase, JSONObject usageObject) {
		System.out.println(useCase.toString());
		JSONArray use = (JSONArray) usageObject.get(useCase.toString());
		Iterator<?> iterator = use.iterator();
		while (iterator.hasNext()) {
			System.out.println(iterator.next());
		}

	}

	/**
	 * Prints all data contained in the JSON file
	 */
	@SuppressWarnings({ "unchecked", "unused" })
	private static void readJSON() {

		try (FileReader reader = new FileReader(getBasePath() + "SCC_Security_Level_5_2020-0.json")) {
			// Read JSON file
			Object obj = jsonParser.parse(reader);

			JSONArray sccList = (JSONArray) obj;
			System.out.println(sccList);

			JSONObject scc = (JSONObject) sccList.get(0);

			String policyName = (String) scc.get("PolicyName");
			System.out.println(policyName);

			JSONArray publisherObject = (JSONArray) scc.get("Publisher");
			publisherObject.forEach(publisher -> getPublisher((JSONObject) publisher));

			String version = (String) scc.get("Version");
			System.out.println(version);

			String policyIssueDate = (String) scc.get("PolicyIssueDate");
			System.out.println(policyIssueDate);

			String expiry = (String) scc.get("Expiry");
			System.out.println(expiry);

			JSONObject usageObject = (JSONObject) scc.get("Usage");
			Arrays.asList(CryptoUseCase.values()).forEach(useCase -> getUsage(useCase, usageObject));

		} catch (IOException | ParseException e) {
			e.printStackTrace();
		}
	}


	protected static String getBasePath() {
		String basePath ="";
		try {
			 basePath = new File(JSONReader.class.getProtectionDomain().getCodeSource().getLocation().toURI()).getPath()
					.replace("\\target\\classes", "");
		} catch (URISyntaxException e) {
			e.printStackTrace();
		}
		return basePath = basePath + "\\src\\configs\\";
	}

	private static ArrayList<String> allFilePaths = new ArrayList<String>();
	protected static void getFiles(String path)
	{
		
		File folder = new File(path);
		File[] listOfFiles = folder.listFiles();
		for (int i = 0; i < listOfFiles.length; i++) {
			
			if (listOfFiles[i].isFile()) {
				allFilePaths.add(path + "\\" + listOfFiles[i].getName());

			}else
			{
				getFiles(path + "\\" + listOfFiles[i].getName());
			}
		}
		
	}
	
	protected static HashMap<String, Integer> levelsNames = new HashMap<String, Integer>();
	protected static HashSet<Integer> levels = new HashSet<Integer>();
	
	protected static void getSecurityLevel()
	{
		int level;
		levels.clear();
		levelsNames.clear();
		for (int i = 0; i < allFilePaths.size(); i++) {
			level = Integer.parseInt(getSecurityLevel(allFilePaths.get(i)));
			levelsNames.put(allFilePaths.get(i), level);
			levels.add(level);
		}
	}
	
	protected static String getLatestSCC(int level) {
		String latest = null;
		ArrayList<String> pathsWithKey = new ArrayList<String>();
		HashMap<String, String> pathVersion = new HashMap<String, String>();
		
		if (levels.contains(level))
		{
			//which file have security level
			for (HashMap.Entry<String, Integer> entry : levelsNames.entrySet()) {
				  if (entry.getValue().equals(level)) {
				    pathsWithKey.add(entry.getKey());
				  }
				}
			
			for (int i = 0; i < pathsWithKey.size(); i++) {
				String version = getVersion(pathsWithKey.get(i));
				pathVersion.put(pathsWithKey.get(i), version);
			}
			
			int highestYear = 2020;
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
		}else {
			throw new IllegalArgumentException("No file for the specified Security Level Number");
		}

	}
	
	protected static int getHighestLevel(HashSet<Integer> level)
	{
		return Collections.max(level);
	}
	
	protected static String parseFiles(String path)
	{
		allFilePaths.clear();
		getFiles(path);
		getSecurityLevel();
		return getLatestSCC(getHighestLevel(levels));
	}
	
}
