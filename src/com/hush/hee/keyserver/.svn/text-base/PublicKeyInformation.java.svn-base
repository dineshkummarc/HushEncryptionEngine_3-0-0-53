package com.hush.hee.keyserver;

import java.io.Serializable;

public class PublicKeyInformation implements Serializable
{
	private static final long serialVersionUID = 3357210468104122291L;

	private String userStatus;

	private Boolean passphraseComponent;

	private String userAlias;

	private PublicKey[] publicKeys;
	
	private GeneratedPassword generatedPassword;

	private String encryptionMethod;
	
	String authenticatedUserAlias;

	public String getAuthenticatedUserAlias()
	{
		return authenticatedUserAlias;
	}

	public void setAuthenticatedUserAlias(String authenticatedUserAlias)
	{
		this.authenticatedUserAlias = authenticatedUserAlias;
	}

	public PublicKey[] getPublicKeys()
	{
		return publicKeys;
	}
	
	public Boolean getPassphraseComponent()
	{
		return passphraseComponent;
	}

	public void setPassphraseComponent(Boolean sharedSecret)
	{
		this.passphraseComponent = sharedSecret;
	}

	public void setPublicKeys(PublicKey[] publicKeys)
	{
		this.publicKeys = publicKeys;
	}
	
	public String getUserAlias()
	{
		return userAlias;
	}

	public void setUserAlias(String userAlias)
	{
		this.userAlias = userAlias;
	}

	public String getUserStatus()
	{
		return userStatus;
	}

	public void setUserStatus(String userStatus)
	{
		this.userStatus = userStatus;
	}

	public GeneratedPassword getGeneratedPassword()
	{
		return generatedPassword;
	}

	public void setGeneratedPassword(GeneratedPassword generatedPassword)
	{
		this.generatedPassword = generatedPassword;
	}

	public String getEncryptionMethod()
	{
		return encryptionMethod;
	}

	public void setEncryptionMethod(String encryptedMethod)
	{
		this.encryptionMethod = encryptedMethod;
	}
}
