/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.pgp;

/**
 * A holder for a feature information as described in RFC 2440 5.2.3.24.
 *
 * @author Brian Smith
 */
public class Features
{
	/**
	 * The definition of a feature.
	 */
	public static final int MODIFICATION_DETECTION = 0x01;

	public boolean modificationDetection = false;

	public Features(byte[] data)
	{
		modificationDetection = (data[0] | MODIFICATION_DETECTION) == data[0];
	}

	public Features()
	{
	}

	public byte[] getBytes()
	{
		byte[] data = new byte[1];
		if (modificationDetection)
			data[0] |= MODIFICATION_DETECTION;
		return data;
	}

}
