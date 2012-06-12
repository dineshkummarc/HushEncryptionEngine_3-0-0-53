/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.pgp;

/**
 * Indicates that an attempt to verify a signature with a particular key
 * failed.
 */
public class InvalidSignatureException extends Exception
{
	private static final long serialVersionUID = -7669919688504044633L;

	public InvalidSignatureException(String message, Throwable cause)
	{
		super(message, cause);
	}

	public InvalidSignatureException(Throwable cause)
	{
		super(cause);
	}

	public InvalidSignatureException()
	{
		super();
	}

	public InvalidSignatureException(String arg0)
	{
		super(arg0);
	}

	public static InvalidSignatureException wrap(String message,
			Exception exception)
	{
		return new InvalidSignatureException(message, exception);
	}
}
