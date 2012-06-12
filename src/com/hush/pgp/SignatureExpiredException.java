/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.pgp;

/**
 * This exception is thrown on an attempt to verify a signature for a time
 * outside of the validity period for the signature.
 * 
 * @author Brian Smith
 */
public class SignatureExpiredException extends Exception
{
	private static final long serialVersionUID = 4516095384301817722L;

	/**
	 * Constructs the exception with a message.
	 * 
	 * @param message the message to associate with the exception
	 */
	public SignatureExpiredException(String message)
	{
		super(message);
	}
}
