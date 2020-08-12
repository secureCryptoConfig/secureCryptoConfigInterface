package org.securecryptoconfig;

import java.util.Set;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;


@JsonAutoDetect(fieldVisibility = Visibility.ANY)
public class SCCInstance {

	private String PolicyName;
	private Set<SCCInstancePublisher> Publisher;
	private int SecurityLevel;
	private String Version;
	private String PolicyIssueDate;
	private String Expiry;
	private SCCInstanceUseCase Usage;
	
	private SCCInstance(String policyName, Set<SCCInstancePublisher> publisher, 
			int securityLevel, String version, String policyIssueDate, String expiry, SCCInstanceUseCase usage)
	{
		this.PolicyName = policyName;
		this.Publisher = publisher;
		this.SecurityLevel = securityLevel;
		this.Version = version;
		this.PolicyIssueDate = policyIssueDate;
		this.Expiry = expiry;
		this.Usage = usage;
	}
	private SCCInstance()
	{}

	protected static String createSCCInstance(String policyName, Set<SCCInstancePublisher> publisher, 
			int securityLevel, String version, String policyIssueDate, String expiry, SCCInstanceUseCase usage) throws JsonProcessingException {
		ObjectMapper mapper = new ObjectMapper();

		return mapper.writeValueAsString(new SCCInstance(policyName, publisher, securityLevel, version, policyIssueDate, expiry, usage));
	}

	protected String getPolicyName() {
		return PolicyName;
	}

	protected void setPolicyName(String policyName) {
		this.PolicyName = policyName;
	}

	protected Set<SCCInstancePublisher> getPublisher() {
		return Publisher;
	}

	protected void setPublisher(Set<SCCInstancePublisher> publisher) {
		this.Publisher = publisher;
	}

	protected int getSecurityLevel() {
		return SecurityLevel;
	}

	protected void setSecurityLevel(int securityLevel) {
		this.SecurityLevel = securityLevel;
	}

	protected String getVersion() {
		return Version;
	}

	protected void setVersion(String version) {
		this.Version = version;
	}

	protected String getPolicyIssueDate() {
		return PolicyIssueDate;
	}

	protected void setPolicyIssueDate(String policyIssueDate) {
		this.PolicyIssueDate = policyIssueDate;
	}

	protected String getExpiry() {
		return Expiry;
	}

	protected void setExpiry(String expiry) {
		this.Expiry = expiry;
	}

	protected SCCInstanceUseCase getUsage() {
		return Usage;
	}

	protected void setUsage(SCCInstanceUseCase usage) {
		this.Usage = usage;
	}
}