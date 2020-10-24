package org.securecryptoconfig;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
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
import java.util.HashSet;
import java.util.stream.Stream;

import org.securecryptoconfig.SCCKey.KeyType;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Class for handling/parsing SCC file content
 * 
 * @author Lisa
 *
 */
public class JSONReader {

	private static org.apache.logging.log4j.Logger logger = org.apache.logging.log4j.LogManager
			.getLogger(JSONReader.class);

	private static ArrayList<Path> allFilePaths = new ArrayList<Path>();
	private static ArrayList<Path> publicKeyPaths = new ArrayList<Path>();
	final protected static HashSet<Integer> levels = new HashSet<Integer>();

	static FileSystem fileSystem;

	protected static boolean isJAR = false;

	private static String signatureAlgo = "EC";

	// Enum representing supported crypto use cases
	protected enum CryptoUseCase {
		SymmetricEncryption, Signing, Hashing, AsymmetricEncryption, PasswordHashing, KeyGeneration;
	}

	/**
	 * Find the path to the specified policyName
	 * 
	 * @param policyName: of the Secure Crypto Config to use
	 * @return instance
	 */
	protected static SCCInstance findPathForPolicy(String policyName) {
		SCCInstance instance = null;
		for (int i = 0; i < instances.size(); i++) {
			if (instances.get(i).getPolicyName().equals(policyName)) {
				instance = instances.get(i);
				break;
			}
		}
		return instance;
	}

	/**
	 * Get all files out of root "configs" directory of given path
	 * 
	 * @param path to root directory "config"
	 */
	private static void getFiles(Path path) {

		URI uri;

		if (SecureCryptoConfig.customPath == false) {
			try {
				uri = JSONReader.class.getResource("/scc-configs").toURI();

				if (uri.getScheme().equals("jar")) {
					fileSystem = FileSystems.newFileSystem(uri, Collections.<String, Object>emptyMap());
					path = fileSystem.getPath("/scc-configs");
					isJAR = true;
				} else {
					path = Paths.get(uri);
					isJAR = false;
				}
			} catch (URISyntaxException | IOException e) {
				logger.fatal("Custom Path invalid or not available", e);
				return;
			}
		}

		Stream<Path> stream = null;
		try {
			stream = Files.walk(path);
			stream.filter(Files::isRegularFile).filter(file -> file.getFileName().toString().endsWith(".json"))
					.forEach(file -> {
						allFilePaths.add(file);

					});
			stream.close();
		} catch (IOException | NullPointerException e) {
			logger.fatal("Path not available or not set", e);
		} finally {
			if (stream != null) {
				stream.close();
			}
		}
	}

	protected static ArrayList<SCCInstance> instances = new ArrayList<SCCInstance>();

	private static void getSCCInstances() {
		levels.clear();
		ObjectMapper objectMapper = new ObjectMapper();
		int level;
		String version;

		try {
			for (int i = 0; i < allFilePaths.size(); i++) {
				if (isJAR == false) {
					SCCInstance sccInstance = objectMapper.readValue(new File(allFilePaths.get(i).toString()),
							SCCInstance.class);
					// check securityLevel, version format
					level = sccInstance.getSecurityLevel();
					version = sccInstance.getVersion();
					if (level > 0 && version.matches("^[2]\\d{3}-\\d+")) {
						levels.add(level);
						instances.add(sccInstance);
					} else {
						break;
					}

				} else {
					InputStream is = org.securecryptoconfig.JSONReader.class
							.getResourceAsStream(allFilePaths.get(i).toString());
					SCCInstance sccInstance = objectMapper.readValue(is, SCCInstance.class);
					level = sccInstance.getSecurityLevel();
					version = sccInstance.getVersion();
					if (level > 0 && version.matches("^[2]\\d{3}-\\d+")) {
						levels.add(level);
						instances.add(sccInstance);
					} else {
						break;
					}
				}
			}
		} catch (IOException e) {
			logger.fatal("Error while trying to access JSON files", e);
		}
	}

	/**
	 * Determines path to latest SCC file with given Security level
	 * 
	 * @param level
	 * @return path to latest SCC file with given Security level
	 */
	protected static SCCInstance getLatestSCC(int level) {
		SCCInstance latest = null;
		ArrayList<SCCInstance> instancesWithLevel = new ArrayList<SCCInstance>();

		if (levels.contains(level)) {
			// which file have security level
			for (SCCInstance instance : instances) {
				if (instance.getSecurityLevel() == level) {
					instancesWithLevel.add(instance);
				}
			}

			int highestYear = 0;
			int highestPatch = 0;

			for (SCCInstance i : instancesWithLevel) {
				String nmb = i.getVersion();
				String version[] = nmb.split("-");
				Integer versionInt[] = new Integer[2];
				versionInt[0] = Integer.parseInt(version[0]);
				versionInt[1] = Integer.parseInt(version[1]);
				if (highestYear < versionInt[0]) {
					latest = i;
					highestYear = versionInt[0];

				} else if (highestYear == versionInt[0]) {
					if (highestPatch < versionInt[1]) {
						highestPatch = versionInt[1];
						latest = i;
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
	 * @param level Hashset with all appearing Security Level numbers
	 * @return highest appearing level
	 */
	protected static int getHighestLevel(HashSet<Integer> level) {

		return Collections.max(level);
	}

	private static boolean checkSignature(String algo, String signaturePath, String publicKeyPath) throws IOException,
			NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException, SCCException {

		byte[] publicKey;
		byte[] sig;
		if (isJAR == false) {
			Path fileLocation = Paths.get(publicKeyPath);
			publicKey = Files.readAllBytes(fileLocation);

			Path fileLocation1 = Paths.get(signaturePath);
			sig = Files.readAllBytes(fileLocation1);

		} else {
			InputStream is = org.securecryptoconfig.JSONReader.class.getResourceAsStream(publicKeyPath);
			publicKey = is.readAllBytes();
			is.close();
			InputStream is1 = org.securecryptoconfig.JSONReader.class.getResourceAsStream(signaturePath);
			sig = is1.readAllBytes();
			is1.close();
		}

		PublicKey pub = KeyFactory.getInstance(algo.toString()).generatePublic(new X509EncodedKeySpec(publicKey));

		SCCKey key = new SCCKey(KeyType.Asymmetric, pub.getEncoded(), null, algo);

		SCCSignature signature = SCCSignature.createFromExistingSignature(sig);

		return signature.validateSignature(key);

	}

	private static void getPublicKeyPath(Path path) {
		URI uri;
		Path p = null;
		try {
			uri = JSONReader.class.getResource("/scc-configs/publicKeys").toURI();

			if (isJAR == true) {
				p = fileSystem.getPath("/scc-configs/publicKeys");
			} else {
				if (SecureCryptoConfig.customPath == false) {
					p = Paths.get(uri);
				} else {
					p = Paths.get(path.toString() + "\\publicKeys");
				}
			}
		} catch (URISyntaxException e) {
			logger.fatal("public key path not valid", e); 
		}
		Stream<Path> s = null;
		try {
			s = Files.walk(p);
			s.filter(Files::isRegularFile).filter(file -> file.getFileName().toString().startsWith("publicKey"))
					.forEach(file -> {
						publicKeyPaths.add(file);

					});
		} catch (IOException e) {
			logger.fatal("Error while trying to access file", e);
		} finally {
			if (s != null) {
				s.close();
			}
		}
	}

	private static void startValidation() throws SCCException {
		InputStream is1;
		InputStream is2;
		for (int i = 0; i < allFilePaths.size(); i++) {
			Path filepath = allFilePaths.get(i);
			String signaturePath1 = filepath.toString();
			String signaturePath2 = filepath.toString();
			String[] parts = allFilePaths.get(i).toString().split("\\\\");
			String signatureFileName1 = parts[parts.length - 1].replace(".json", "-signature1");
			String signatureFileName2 = parts[parts.length - 1].replace(".json", "-signature2");
			signaturePath1 = filepath.toString().replace(parts[parts.length - 1], "") + signatureFileName1;
			signaturePath2 = filepath.toString().replace(parts[parts.length - 1], "") + signatureFileName2;

			boolean validation1 = false;
			boolean validation2 = false;
			boolean result;
			if (isJAR == false) {
				result = new File(signaturePath1).exists() && new File(signaturePath2).exists();
			} else {
				is1 = org.securecryptoconfig.JSONReader.class.getResourceAsStream(signaturePath1);
				is2 = org.securecryptoconfig.JSONReader.class.getResourceAsStream(signaturePath2);
				result = is1 != null && is2 != null;
				try {
					if (is1 != null) {
						is1.close();
					}
					if (is2 != null) {
						is2.close();
					}
				} catch (IOException e) {
					logger.fatal("Error while trying to validate JSON files", e);
				}

			}

			if (result) {

				try {
					validation1 = checkSignature(signatureAlgo, signaturePath1, publicKeyPaths.get(0).toString());
					validation2 = checkSignature(signatureAlgo, signaturePath2, publicKeyPaths.get(1).toString());
				} catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | SignatureException
						| IOException e) {
					throw new SCCException("Signature check of Secure Crypto Config files could not be performed!", e);
				}
				if (validation1 != true || validation2 != true) {
					logger.debug("Not both signatures are valid for {}", filepath);
					logger.debug("This file will not be considered!");
					allFilePaths.remove(i);
				}
			} else {
				logger.debug("There are no two signatures defined for {}", filepath);
				logger.debug("This file will not be considered!");
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
	protected static SCCInstance parseFiles(Path path) {
		publicKeyPaths.clear();
		allFilePaths.clear();
		instances.clear();

		getFiles(path);
		getSCCInstances();
		getPublicKeyPath(path);

		try {
			startValidation();
		} catch (SCCException e) {
			e.printStackTrace();
		}

		return getLatestSCC(getHighestLevel(levels));

	}

}
