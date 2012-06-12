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
 * A stream to write out a PGP public subkey.
 *
 *
 * @author Brian Smith
 *
 */
public class PublicSubkeyOutputStream extends PublicKeyOutputStream
{
	/**
	 * @param out
	 * @param key
	 * @throws IOException
	 */
	public PublicSubkeyOutputStream(OutputStream out, Key key)
		throws IOException
	{
		super(out, key, PACKET_TAG_PUBLIC_SUBKEY);
	}
}
