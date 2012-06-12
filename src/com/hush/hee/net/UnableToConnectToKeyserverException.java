package com.hush.hee.net;

import com.hush.hee.KeyStoreException;

public class UnableToConnectToKeyserverException extends KeyStoreException
{

	private static final long serialVersionUID = 6641959053644625629L;

	public UnableToConnectToKeyserverException(String message)
	{
		super(message);
	}
}
