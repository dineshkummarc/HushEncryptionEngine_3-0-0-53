/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.util;

public class UnrecoverableKeyException extends RuntimeException
{
	private static final long serialVersionUID = -5620670468481017550L;

	public UnrecoverableKeyException()
	{
		super();
	}
	
	public UnrecoverableKeyException(String message)
	{
		super(message);
	}
	
	public UnrecoverableKeyException(String message, Throwable cause)
	{
		super(message, cause);
	}

	public UnrecoverableKeyException(Throwable cause)
	{
		super(cause);
	}
	
	public static UnrecoverableKeyException wrap(String message, Throwable e)
	{
		return new UnrecoverableKeyException(message, e);
	}
}
