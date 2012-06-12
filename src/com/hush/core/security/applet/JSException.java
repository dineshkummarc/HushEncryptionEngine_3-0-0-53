/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.core.security.applet;

/**
 * JSException is used report Java exceptions to Javascript clients.
 * Since Javascript cannot handle exceptions this class logs the exception and provides static methods to check for the last error.
 *
 * @copyright   Copyright (c) 2000 by Hush Communications Corporation.
 */
public class JSException
{
	static private boolean lastError = false;
	static private String lastErrorMsg = "";

	/**
	 * Stores the exception message and sets the state of the last error condition.
	 */
	public JSException(Throwable throwable)
	{
		lastErrorMsg = throwable.toString();
		throwable.printStackTrace();
		lastError = true;
	}

	/**
	 * Removes last error information.
	 */
	public static void resetLastError()
	{
		lastError = false;
		lastErrorMsg = "";
	}

	/**
	 * Indicates if a new exception has been thrown since the previous error (previous getLastError or
	 * resetLastError or getLastError msg call).
	 * @return true if exception has occured, false otherwise.
	 */
	public static boolean getLastError()
	{
		boolean error = lastError;
		lastError = false;

		return error;
	}

	/**
	 * Gets the error message associated with the previous exception.
	 * @return last exception message.
	 */
	public static String getLastErrorMsg()
	{
		String retVal = lastErrorMsg;
		resetLastError();

		return retVal;
	}
}