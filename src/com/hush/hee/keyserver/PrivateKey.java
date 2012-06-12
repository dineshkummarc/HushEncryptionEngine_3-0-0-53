package com.hush.hee.keyserver;

import java.io.Serializable;

public class PrivateKey implements Serializable
{
	private static final long serialVersionUID = -5170112778630733357L;
	private String index;
	private String encryptedPrivateKey;
	private Boolean isMainKey;
	public String getIndex()
	{
		return index;
	}
	public void setIndex(String index)
	{
		this.index = index;
	}
	public String getEncryptedPrivateKey()
	{
		return encryptedPrivateKey;
	}
	public void setEncryptedPrivateKey(String encryptedPrivateKey)
	{
		this.encryptedPrivateKey = encryptedPrivateKey;
	}
	public Boolean getIsMainKey()
	{
		return isMainKey;
	}
	public void setIsMainKey(Boolean mainKey)
	{
		this.isMainKey = mainKey;
	}
}
