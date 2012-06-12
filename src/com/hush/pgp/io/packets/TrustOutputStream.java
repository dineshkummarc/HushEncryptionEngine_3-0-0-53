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

/**
 * A stream to write out PGP trust information.
 *
 *
 * @author Brian Smith
 *
 */
public class TrustOutputStream extends PacketContentOutputStream
{

	/**
	 * Constructor for an output stream that writes trust information.
	 * 
	 * @param out the stream to which the trust information will be written
	 */
	public TrustOutputStream(OutputStream out) throws IOException
	{
		super(out, PACKET_TAG_TRUST);
	}

	public void engineInit() throws IOException
	{
	}
}