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

import com.hush.pgp.DataFormatException;
import com.hush.util.Conversions;
import com.hush.util.Logger;

/**
 * A stream to read PGP literal data.
 * <br>
 * Note: This stream performs no newline/CRLF conversions.
 *
 * @author Brian Smith
 *
 */
public class LiteralDataInputStream extends PacketContentInputStream
{
	private boolean isText;
	private byte[] filename;
	private long time;
	/**
	 * Creates a <code>LiteralDataInputStream</code> and saves the argument,
	 * the input stream <code>in</code> for later use.  In most cases
	 * <code>in</code> should be a <code>PacketInputStream</code>.
	 * 
	 * @param in the underlying input stream
	 */
	public LiteralDataInputStream(InputStream in)
	{
		super(in, PACKET_TAG_LITERAL_DATA);
	}

	/**
	 * Returns the date recorded with the literal data.
	 * 
	 * @return the date
	 * @throws DataFormatException if there is a problem with the PGP data
	 * @throws IOException if an exception is thrown from the underyling stream
	 */
	public long getTime() throws DataFormatException, IOException
	{
		init();
		return time;
	}

	/**
	 * Returns the filename recorded with the literal data.
	 * 
	 * @return the filename
	 * @throws DataFormatException if there is a problem with the PGP data
	 * @throws IOException if an exception is thrown from the underyling stream
	 */
	public byte[] getFilename() throws DataFormatException, IOException
	{
		init();
		return filename;
	}

	protected void engineInit() throws DataFormatException, IOException
	{
		// Get text or binary
		int octet = read();
		if (octet == -1)
			throw new DataFormatException("Unexpected EOF while reading text/binary flag");
		Logger.log(this, Logger.DEBUG, "Text/binary flag: " + octet);
		switch (octet)
		{
			case 0x74 :
				isText = true;
				break;
			case 0x62 :
				isText = false;
				break;
			default :
				Logger.log(
					this,
					Logger.DEBUG,
					"Unknown data type (assuming binary): " + octet);
				isText = false;
		}
		Logger.log(this, Logger.DEBUG, "Text data: " + isText);
		// Get the filename if there is one
		octet = read();
		if (octet == -1)
			throw new DataFormatException("Unexpected EOF while reading filename length");
		if (octet > 0)
		{
			filename = new byte[octet];
			if (read(filename) != filename.length)
				new DataFormatException("Unexpected EOF while reading filename");
			Logger.log(this, Logger.DEBUG, "Filename length: " + octet);
		}
		// Get the date
		byte[] timeBytes = new byte[4];
		if (read(timeBytes) != 4)
			throw new DataFormatException("Unexpected EOF while reading date");
		time = Conversions.bytesToLong(timeBytes);
		Logger.hexlog(this, Logger.DEBUG, "Time field: ", timeBytes);
		Logger.log(this, Logger.DEBUG, "Time: " + time);
	}
}