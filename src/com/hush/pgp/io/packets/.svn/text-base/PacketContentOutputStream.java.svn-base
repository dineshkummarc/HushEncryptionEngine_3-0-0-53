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

import com.hush.pgp.PgpConstants;
import com.hush.util.Logger;

/**
 * A stream to write the content of a PGP packet. It's sole purpose is
 * to provide an interface for initialization of the data to be written
 * to the packet.
 *
 * @author Brian Smith
 *
 */
public abstract class PacketContentOutputStream
	extends OutputStream
	implements PgpConstants
{
	private OutputStream out;
	private boolean initing = false;
	private boolean inited = false;

	/**
	 * Creates a <code>PacketContentOutputStream</code> and saves the arguments
	 * for later use.  In most cases <code>out</code> should be a 
	 * <code>PacketInputStream</code>.
	 * 
	 * @param out the underlying output stream.
	 * @param type the underlying packet type.
	 * @see com.hush.pgp.PgpConstants
	 * @see com.hush.pgp.io.packets.PacketOutputStream
	 */
	protected PacketContentOutputStream(OutputStream out, int type)
	{
		this(out, type, -1);
	}

	/**
	 * Creates a <code>PacketContentOutputStream</code> and saves the arguments
	 * for later use.  In most cases <code>out</code> should be a 
	 * <code>PacketInputStream</code>.
	 * 
	 * @param out the underlying output stream.
	 * @param type the underlying packet type.
	 * @see com.hush.pgp.PgpConstants
	 * @see com.hush.pgp.io.packets.PacketOutputStream
	 */
	protected PacketContentOutputStream(
		OutputStream out,
		int type,
		long length)
	{
		this.out = out;
		if (out instanceof PacketOutputStream)
		{
			PacketOutputStream pgpOut = (PacketOutputStream) out;
			pgpOut.setType(type);
			pgpOut.setLength(length);
		}
	}

	/**
	 * Sets the length of the packet. Cannot be called after data is
	 * written to the stream.
	 * 
	 * @param length the packet length.
	 */
	public void setLength(long length)
	{
		if (out instanceof PacketOutputStream)
		{
			PacketOutputStream pgpOut = (PacketOutputStream) out;
			pgpOut.setLength(length);
		}
	}

	/**
	 * Returns the expected length of the packet that will be generated.
	 * If we are dealing with partial lengths, this will return -1.
	 *
	 * @return the expected packet length.
	 */
	//TODO: Clear out these comments	
	/*
	public long getExpectedPacketLength()
	{
		if ( out instanceof PacketOutputStream )
		{
			PacketOutputStream pgpOut = (PacketOutputStream)out;
			return pgpOut.getExpectedPacketLength();
		}
		else
			throw new IllegalStateException(
				"Internal stream is not a PacketOutputStream");
	}
	*/

	/**
	 * @see java.io.OutputStream#write(int)
	 */
	public void write(int b) throws IOException
	{
		init();
		out.write(b);
	}

	/**
	 * @see java.io.OutputStream#write(byte[])
	 */
	public void write(byte[] b) throws IOException
	{
		init();
		out.write(b);
	}

	/**
	 * @see java.io.OutputStream#write(byte[], int, int)
	 */
	public void write(byte[] b, int offset, int len) throws IOException
	{
		init();
		out.write(b, offset, len);
	}

	/**
	 * Flushes the underlying stream.
	 * 
	 * @see java.io.OutputStream#flush()
	 */
	public void flush() throws IOException
	{
		init();
		out.flush();
	}

	/**
	 * Closes this stream and the underlying stream.
	 * 
	 * @see java.io.OutputStream#close()
	 */
	public void close() throws IOException
	{
		Logger.log(this, Logger.DEBUG, "Closing stream");
		init();
		out.close();
	}

	protected final void init() throws IOException
	{
		if (initing || inited)
			return;
		initing = true;
		engineInit();
		inited = true;
		initing = false;
	}

	protected abstract void engineInit() throws IOException;

}