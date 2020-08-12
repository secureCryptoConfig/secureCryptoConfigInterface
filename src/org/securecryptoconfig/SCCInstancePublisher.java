package org.securecryptoconfig;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility;

@JsonAutoDetect(fieldVisibility = Visibility.ANY)
public class SCCInstancePublisher {
	private String name;
	private String URL;
	protected String getName() {
		return name;
	}
	protected void setName(String name) {
		this.name = name;
	}
	protected String getURL() {
		return URL;
	}
	protected void setURL(String uRL) {
		URL = uRL;
	}
}
