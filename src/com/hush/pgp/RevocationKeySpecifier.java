/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.pgp;

import java.io.Serializable;

/**
 * A holder for revocation key information as described in
 * RFC 2440 5.2.3.15.
 *
 * @author Brian Smith
 */
public class RevocationKeySpecifier implements Serializable
{
	private static final long serialVersionUID = -6810805647255073942L;
	private static final int sensitiveFlag = 0x40;
	private boolean sensitive;
	private byte[] fingerprint = new byte[20];
	private int algorithm;

	public RevocationKeySpecifier(byte[] data)
	{
		if ((data[0] | 0x80) != data[0])
			throw new IllegalArgumentException("High bit of class must be set");
		sensitive = ((data[0] | 0x40) == data[0]);
		algorithm = data[1];
		System.arraycopy(data, 2, fingerprint, 0, 20);
	}

	public RevocationKeySpecifier(
		byte[] fingerprint,
		int algorithm,
		boolean sensitive)
	{
		this.fingerprint = fingerprint;
		this.algorithm = algorithm;
		this.sensitive = sensitive;
	}

	public byte[] getBytes()
	{
		byte[] returnBytes = new byte[22];
		returnBytes[0] = (byte) 0;
		returnBytes[0] |= 0x80;
		if (sensitive)
			returnBytes[0] |= sensitiveFlag;
		returnBytes[1] = (byte) algorithm;
		System.arraycopy(fingerprint, 0, returnBytes, 2, fingerprint.length);
		return returnBytes;
	}

	public byte[] getFingerprint()
	{
		return fingerprint;
	}

	public boolean getSensitive()
	{
		return sensitive;
	}

	public int getAlgorithm()
	{
		return algorithm;
	}
}