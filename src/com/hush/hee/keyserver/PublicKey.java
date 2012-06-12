package com.hush.hee.keyserver;

import java.io.Serializable;

public class PublicKey implements Serializable
{
	private static final long serialVersionUID = -3976258132572055599L;
	private String keyID;
	private String key;
	private boolean isAdk;
	public String getKeyID()
	{
		return keyID;
	}
	public void setKeyID(String keyID)
	{
		this.keyID = keyID;
	}
	public String getKey()
	{
		return key;
	}
	public void setKey(String key)
	{
		this.key = key;
	}
	public boolean getIsAdk()
	{
		return isAdk;
	}
	public void setIsAdk(boolean isAdk)
	{
		this.isAdk = isAdk;
	}
}
