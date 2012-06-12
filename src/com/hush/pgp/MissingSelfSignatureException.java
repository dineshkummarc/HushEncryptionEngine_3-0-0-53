/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.pgp;

/**
 * This exception is thrown if a self-signature on a key or certification
 * is missing.
 * 
 * @author Brian Smith
 */
public class MissingSelfSignatureException extends Exception
{
	private static final long serialVersionUID = -1209167047423314499L;

	public MissingSelfSignatureException()
	{
		super();
	}

	public MissingSelfSignatureException(String arg0)
	{
		super(arg0);
	}
}
