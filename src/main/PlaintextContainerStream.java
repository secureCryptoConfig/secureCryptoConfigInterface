package main;

import java.io.File;
import java.io.FileNotFoundException;

public class PlaintextContainerStream extends AbstractPlaintextContainerStream{

	public PlaintextContainerStream(File file) throws FileNotFoundException {
		super(file);
	}

}
