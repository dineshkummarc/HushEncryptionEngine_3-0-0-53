/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.hee;

import com.hush.util.Logger;

/**
 * This exception indicates that the key server returned an unexpected
 * response or a response containing data that the client was unable to
 * interpret.
 * 
 * This exception is not thrown on a failure to connect to the key server.
 * That will throw an IOException.
 */
public class KeyStoreException extends Exception
{
	private static final long serialVersionUID = 1198740289200131683L;
	
	public KeyStoreException(String message, Throwable cause)
	{
		super(message, cause);
	}

	public KeyStoreException(Throwable cause)
	{
		super(cause);
	}

	public KeyStoreException(String arg0)
	{
		super(arg0);
	}
	
	public KeyStoreException()
	{
		super();
	}
	
	public static KeyStoreException wrapInKeyStoreException(String message,
			Exception exception)
	{
		return new KeyStoreException(message, exception);
	}
}
