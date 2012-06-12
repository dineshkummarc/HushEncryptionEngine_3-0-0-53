/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.pgp.io.packets;

import java.io.InputStream;

/**
 * A stream to read in a PGP secret subkey.
 * <br>
 * The getters should be used to retrieve all information from this stream.
 * The standard <code>read</code> methods will just return EOF.
 *
 * @author Brian Smith
 *
 */
public class SecretSubkeyInputStream
	extends SecretKeyInputStream
{
	/**
	 * Creates a <code>SecretSubkeyInputStream</code> and saves the argument,
	 * the input stream <code>in</code> for later use.  In most cases
	 * <code>in</code> should be a <code>PacketInputStream</code>.
	 * 
	 * @param in the underlying input stream.
	 */
	public SecretSubkeyInputStream(InputStream in)
	{
		super(in, PACKET_TAG_SECRET_SUBKEY);
	}
}
