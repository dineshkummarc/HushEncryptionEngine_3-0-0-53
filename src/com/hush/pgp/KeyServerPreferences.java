/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.pgp;

/**
 * A holder for key server preferences information as described in
 * RFC 2440 5.2.3.17.
 *
 * @author Brian Smith
 */
public class KeyServerPreferences
{

	/**
	 * If true, indicates that the key on the key server should only be
	 * modified by the owner or the key server administrator.
	 */
	boolean noModify = false;

	private static final int noModifyFlag = 0x80;

	public KeyServerPreferences()
	{
	}

	public KeyServerPreferences(byte[] data)
	{
		noModify = ((noModifyFlag | data[0]) == data[0]);
	}

	/**
	 * Gets the byte array representation of the key server
	 * preferences.
	 */
	public byte[] getBytes()
	{
		byte[] returnBytes = new byte[1];
		if (noModify)
			returnBytes[0] |= noModifyFlag;
		return returnBytes;
	}
}
