/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.pgp.io.packets;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import com.hush.pgp.DataFormatException;
import com.hush.pgp.UserAttribute;

/**
 * A stream to read in a PGP user attribute.
 * <br>
 * The getters should be used to retrieve all information from this stream.
 * The standard <code>read</code> methods will just return EOF.
 *
 * @author Brian Smith
 *
 */
public class UserAttributeInputStream extends PacketContentInputStream
{
	UserAttribute userAttribute = new UserAttribute();

	/**
	 * Creates a 
	 * <code>UserIDInputStream</code>
	 * and saves the argument, the input stream <code>in</code> for later use.
	 * In most cases <code>in</code> should be a
	 * <code>PacketInputStream</code>.
	 * 
	 * @param in the underlying input stream.
	 */
	public UserAttributeInputStream(InputStream in)
	{
		super(in, PACKET_TAG_USER_ATTRIBUTE);
	}

	/**
	 * Returns the user attribute in a <code>UserID</code> object.
	 * 
	 * @return the user attribute.
	 * @throws DataFormatException if there is a problem with the PGP data
	 * @throws IOException if an exception is thrown from the underyling stream
	 */
	public UserAttribute getUserAttribute()
		throws DataFormatException, IOException
	{
		init();
		return userAttribute;
	}

	protected void engineInit() throws DataFormatException, IOException
	{

		ByteArrayOutputStream data = new ByteArrayOutputStream();
		int x;
		while ((x = in.read()) != -1)
		{
			data.write(x);
		}

		userAttribute.setContent(data.toByteArray());
	}
}
