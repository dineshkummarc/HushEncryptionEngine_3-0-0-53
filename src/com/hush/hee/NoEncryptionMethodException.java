package com.hush.hee;

import com.hush.util.Logger;

/**
 * This exception indicates that the key server could not find an encryption
 * method for this alias - meaning that no public key is available for
 * encryption and the customer who owns this alias does not have another
 * method of encryption available, such as generated passwords.
 */
public class NoEncryptionMethodException extends KeyStoreException
{
	private static final long serialVersionUID = -3052673982680106638L;

	public NoEncryptionMethodException()
	{
		super();
	}

	public NoEncryptionMethodException(String message)
	{
		super(message);
	}

	public NoEncryptionMethodException(String message, Throwable cause)
	{
		super(message, cause);
	}

	public NoEncryptionMethodException(Throwable cause)
	{
		super(cause);
	}
	
	public static NoEncryptionMethodException wrapInNoEncryptionMethodException(String message,
			Exception exception)
	{
		return new NoEncryptionMethodException(message, exception);
	}
}
