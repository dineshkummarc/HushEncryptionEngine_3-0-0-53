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

/**
 * A stream to read in a PGP secret key
 * <br>
 * The getters should be used to retrieve all information from this stream.
 * The standard <code>read</code> methods will just return EOF.
 * 
 * @author Brian Smith
 *
 */
public class SecretKeyInputStream extends PublicKeyInputStream
{
	/**
	 * Creates a <code>SecretKeyInputStream</code> and saves the argument,
	 * the input stream <code>in</code> for later use.  In most cases
	 * <code>in</code> should be a <code>PacketInputStream</code>.
	 * 
	 * @param in the underlying input stream
	 */
	public SecretKeyInputStream(InputStream in)
	{
		this(in, PACKET_TAG_SECRET_KEY);
	}

	protected SecretKeyInputStream(InputStream in, int packetTag)
	{
		super(in, packetTag);
	}

	/**
	 * @see com.hush.pgp.io.packets.PublicKeyInputStream#readSecretKeyMaterial()
	 */
	protected void readSecretKeyMaterial()
		throws DataFormatException, IOException
	{
		// Read the remaining bytes of the packet into a buffer
		ByteArrayOutputStream secretKeyMaterialStream =
			new ByteArrayOutputStream();
		byte[] b = new byte[512];
		int len;
		while ((len = read(b)) != -1)
			secretKeyMaterialStream.write(b, 0, len);
		key.setSecretKeyMaterial(secretKeyMaterialStream.toByteArray());
	}

}
