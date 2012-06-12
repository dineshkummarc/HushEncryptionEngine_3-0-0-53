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

import com.hush.util.Conversions;
import com.hush.util.Logger;

/**
 * A stream to write out PGP literal data.
 * <br>
 * Note: This stream performs no newline/CRLF conversions.
 *
 * @author Brian Smith
 *
 */
public class LiteralDataOutputStream extends PacketContentOutputStream
{
	private long time = System.currentTimeMillis() / 1000;
	private byte[] filename = null;
	private boolean text = false;

	/**
	 * Creates a <code>LiteralDataOutputStream</code> and saves the arguments
	 * for later use.  In most cases <code>out</code> should be a 
	 * <code>PacketInputStream</code>.
	 * 
	 * @param out the underlying output stream.
	 * @see com.hush.pgp.io.packets.PacketOutputStream
	 */
	public LiteralDataOutputStream(OutputStream out)
	{
		super(out, PACKET_TAG_LITERAL_DATA);
	}

	/**
	 * Creates a <code>LiteralDataOutputStream</code> and saves the arguments
	 * for later use.  In most cases <code>out</code> should be a 
	 * <code>PacketInputStream</code>.
	 * 
	 * @param out the underlying output stream.
	 * @param text true if data is text; false if it is binary.
	 * @param filename the filename associated with the data, or null if none.
	 * @param time the time in seconds since midnight, 1 January 1970 UTC.
	 * @see com.hush.pgp.io.packets.PacketOutputStream
	 */
	public LiteralDataOutputStream(
		OutputStream out,
		boolean text,
		byte[] filename,
		long time)
	{
		super(out, PACKET_TAG_LITERAL_DATA);
		this.text = text;
		this.filename = filename;
		this.time = time;
	}

	/**
	 * Creates a <code>LiteralDataOutputStream</code> and saves the arguments
	 * for later use.  In most cases <code>out</code> should be a 
	 * <code>PacketInputStream</code>.
	 * 
	 * @param out the underlying output stream.
	 * @param text true if data is text; false if it is binary.
	 * @param filename the filename associated with the data, or null if none.
	 * @param time the time in seconds since midnight, 1 January 1970 UTC.
	 * @param length the length of the data to be written to the stream.
	 * @see com.hush.pgp.io.packets.PacketOutputStream
	 */
	public LiteralDataOutputStream(
		OutputStream out,
		boolean text,
		byte[] filename,
		long time,
		long length)
	{
		super(out, PACKET_TAG_LITERAL_DATA);
		this.text = text;
		this.filename = filename;
		this.time = time;
		setLength(length);
	}

	/**
	 * Sets the length of the data to be written. Cannot be called after data is
	 * written to the stream.
	 * 
	 * @param length the packet length.
	 */
	public void setLength(long length)
	{
		super.setLength(
			(length == -1)
				? -1
				: length + 6 + (filename == null ? 0 : filename.length));
	}

	protected void engineInit() throws IOException
	{
		if (filename == null)
			filename = new byte[0];
		Logger.log(this, Logger.DEBUG, "Time: " + time);
		byte[] timeField = new byte[4];
		Conversions.longToBytes(time, timeField, 0, 4);
		write(text ? 0x74 : 0x62);
		write(filename.length);
		if (filename.length > 0)
			write(filename);
		filename = null;
		write(timeField);
		Logger.hexlog(this, Logger.DEBUG, "Time field: ", timeField);
	}

}