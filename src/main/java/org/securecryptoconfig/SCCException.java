package org.securecryptoconfig;

/**
 * General Exception of the Secure Crypto Config.
 * 
 * @author Kai
 *
 */
public class SCCException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 5144625194795891055L;

	public SCCException(String errorMessage, Throwable err) {
		super(errorMessage, err);
	}
}
