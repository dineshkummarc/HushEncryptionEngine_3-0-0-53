/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.pgp.io.packets;

import java.io.IOException;
import java.io.OutputStream;

import com.hush.pgp.Key;

/**
 * A stream to write out a PGP secret subkey.
 *
 *
 * @author Brian Smith
 *
 */
public class SecretSubkeyOutputStream extends SecretKeyOutputStream
{

	/**
	 * Constructor for an output stream that generates a PGP secret subkey.
	 * 
	 * @param out the stream to which the public key will be written
	 * @param key the key to write to the packet
	 */
	public SecretSubkeyOutputStream(OutputStream out, Key key)
		throws IOException
	{
		super(out, key, PACKET_TAG_SECRET_SUBKEY);
	}

}
