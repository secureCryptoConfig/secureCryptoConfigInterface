package main;

public class SCCException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 5144625194795891055L;

	public SCCException(String errorMessage, Throwable err) {
		super(errorMessage, err);
	}
}
