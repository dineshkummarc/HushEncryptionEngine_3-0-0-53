package com.hush.hee;

public class BadRequestException extends KeyStoreException
{
	private static final long serialVersionUID = -2884301065562070228L;
	
	public BadRequestException(String message, Throwable cause)
	{
		super(message, cause);
	}

	public BadRequestException(Throwable cause)
	{
		super(cause);
	}

	public BadRequestException()
	{
		super();
	}

	public BadRequestException(String message)
	{
		super(message);
	}
}
