package com.hush.hee.keyserver;

import java.io.Serializable;
import java.util.Date;

public class PrivateKeyInformation implements Serializable
{
	private static final long serialVersionUID = -7543096089576930366L;
	private com.hush.hee.keyserver.PrivateKey[] encryptedPrivateKeys;
	private String encryptedRandomSeed;
	private Date lastAccessTime;
	public com.hush.hee.keyserver.PrivateKey[] getEncryptedPrivateKeys()
	{
		return encryptedPrivateKeys;
	}
	public void setEncryptedPrivateKeys(com.hush.hee.keyserver.PrivateKey[] encryptedPrivateKeys)
	{
		this.encryptedPrivateKeys = encryptedPrivateKeys;
	}
	public String getEncryptedRandomSeed()
	{
		return encryptedRandomSeed;
	}
	public void setEncryptedRandomSeed(String encryptedRandomSeed)
	{
		this.encryptedRandomSeed = encryptedRandomSeed;
	}
	public Date getLastAccessTime()
	{
		return lastAccessTime;
	}
	public void setLastAccessTime(Date lastAccessTime)
	{
		this.lastAccessTime = lastAccessTime;
	}
}
