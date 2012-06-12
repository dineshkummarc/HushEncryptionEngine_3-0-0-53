/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.pgp.cfb;

import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Parameters for PGPCFB mode.
 * 
 * @author Brian Smith (based on Bouncy Castle code)
 */
public class CFBParameters implements CipherParameters
{
	private byte[] initBytes;
	private CipherParameters parameters;

	public CFBParameters(CipherParameters parameters)
	{
		if (!(parameters instanceof KeyParameter))
		{
			throw new IllegalArgumentException("Must initialize with KeyParameter");
		}
		this.parameters = parameters;
	}

	public CFBParameters(CipherParameters parameters, byte[] initBytes)
	{
		if (!(parameters instanceof KeyParameter))
		{
			throw new IllegalArgumentException("Must initialize with KeyParameter");
		}
		this.parameters = parameters;
		this.initBytes = initBytes;
	}

	public byte[] getInitBytes()
	{
		return initBytes;
	}

	public void setInitBytes(byte[] initBytes)
	{
		this.initBytes = initBytes;
	}

	public CipherParameters getParameters()
	{
		return parameters;
	}
}
