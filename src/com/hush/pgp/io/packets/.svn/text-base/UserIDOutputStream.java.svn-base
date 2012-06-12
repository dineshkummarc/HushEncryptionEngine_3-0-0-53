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

import com.hush.pgp.UserID;

/**
 * A stream to write out a PGP user ID.
 *
 *
 * @author Brian Smith
 *
 */
public class UserIDOutputStream extends PacketContentOutputStream
{
	private UserID userID;

	/**
	 * Constructor for an output stream that generates a PGP user ID.
	 * 
	 * @param out the stream to which the public key will be written
	 * @param userID the user ID to write to the packet
	 */
	public UserIDOutputStream(OutputStream out, UserID userID)
		throws IOException
	{
		super(out, PACKET_TAG_USER_ID);
		this.userID = userID;
	}
	
	public void engineInit() throws IOException
	{
		setLength(userID.getBytes().length);
		write(userID.getBytes());
		userID = null;
	}
}