/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.pgp;

import java.io.Serializable;

import com.hush.util.Conversions;

/**
 * A holder for a reason for revocation as described in RFC 2440 5.2.3.23.
 *
 * @author Brian Smith
 */
public class RevocationReason implements Serializable
{
	private static final long serialVersionUID = 617248104166796038L;
	int revocationCode;
	byte[] reason;

	/**
	 * Definition of a revocation reason.
	 */
	public static final int NO_REASON = 0x00;

	/**
	 * Definition of a revocation reason.
	 */
	public static final int KEY_SUPERSEDED = 0x01;

	/**
	 * Definition of a revocation reason.
	 */
	public static final int KEY_MATERIAL_COMPROMISED = 0x02;

	/**
	 * Definition of a revocation reason.
	 */
	public static final int KEY_IS_RETIRED = 0x03;

	/**
	 * Definition of a revocation reason.
	 */
	public static final int USER_ID_NO_LONGER_VALID = 0x20;

	public RevocationReason(byte[] data)
	{
		revocationCode = Conversions.unsignedByteToInt(data[0]);
		reason = new byte[data.length - 1];
		System.arraycopy(data, 1, reason, 0, reason.length);
	}

	public RevocationReason(int revocationCode, byte[] reason)
	{
		this.revocationCode = revocationCode;
		this.reason = reason;
	}

	public byte[] getBytes()
	{
		byte[] data = new byte[reason.length + 1];
		data[0] = (byte) revocationCode;
		System.arraycopy(reason, 0, data, 1, reason.length);
		return data;
	}

	/**
	 * Returns the revocation code.
	 */
	public int getRevocationCode()
	{
		return revocationCode;
	}

	/**
	 * Returns the revocation reason string.
	 */
	public byte[] getReason()
	{
		return reason;
	}
}
