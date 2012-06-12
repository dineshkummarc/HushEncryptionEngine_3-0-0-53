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
 * A stream to read in a PGP public subkey.
 * <p>
 * The getters should be used to retrieve all information from this stream.
 * <p>
 * The standard <code>read</code> methods will just return EOF.
 *
 * @author Brian Smith
 *
 */
public class PublicSubkeyInputStream extends PublicKeyInputStream
{
	/**
	 * Creates a <code>PublicSubkeyInputStream</code> and saves the argument,
	 * the input stream <code>in</code> for later use.  In most cases
	 * <code>in</code> should be a <code>PacketInputStream</code>.
	 * 
	 * @param in the underlying input stream
	 */
	public PublicSubkeyInputStream(InputStream in)
	{
		super(in, PACKET_TAG_PUBLIC_SUBKEY);
	}
}
