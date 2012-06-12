/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.pgp.io.packets;

import java.io.IOException;
import java.io.InputStream;

/**
 * A stream to read in PGP trust information.
 *
 * @author Brian Smith
 *
 */
public class TrustInputStream
	extends PacketContentInputStream
{
	/**
	 * Creates a 
	 * <code>TrustInputStream</code>
	 * and saves the argument, the input stream <code>in</code> for later use.
	 * In most cases <code>in</code> should be a
	 * <code>PacketInputStream</code>.
	 * 
	 * @param in the underlying input stream.
	 */
	public TrustInputStream(InputStream in)
	{
		super(in, PACKET_TAG_TRUST);
	}
	
	protected void engineInit() throws IOException
	{
	}
}
