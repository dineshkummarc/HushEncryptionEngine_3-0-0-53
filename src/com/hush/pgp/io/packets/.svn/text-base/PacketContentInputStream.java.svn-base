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
import com.hush.pgp.PgpConstants;
import com.hush.util.Logger;

/**
 * A stream to read the content of a PGP packet.  It's sole purpose
 * is to confirm that, if the underlying stream is a 
 * <code>PgpPacketInputStream</code>, that stream encapsulates a packet of the
 * correct type.
 *
 * @author Brian Smith
 *
 */
public abstract class PacketContentInputStream
	extends InputStream
	implements PgpConstants
{
	protected InputStream in;
	private boolean inited = false;
	private boolean initing = false;
	private int type;

	/**
	 * Creates a <code>PacketContentInputStream</code> and saves the arguments
	 * for later use.  In most cases <code>in</code> should be a 
	 * <code>PacketInputStream</code>.
	 * 
	 * @param in the underlying input stream.
	 * @param type the underlying packet type.
	 * @see com.hush.pgp.PgpConstants
	 * @see com.hush.pgp.io.packets.PacketInputStream
	 */
	protected PacketContentInputStream(InputStream in, int type)
	{
		this.in = in;
		this.type = type;
	}

	/**
	 * @see java.io.InputStream#available()
	 * @throws DataFormatException if there is a problem with the PGP data
	 * @throws IOException if an exception is thrown from the underyling stream
	 */
	public int available() throws DataFormatException, IOException
	{
		throw new RuntimeException("Not supported");
	}

	/**
	 * @see java.io.InputStream#close()
	 * @throws DataFormatException if there is a problem with the PGP data
	 * @throws IOException if an exception is thrown from the underyling stream
	 */
	public void close() throws DataFormatException, IOException
	{
		init();
		in.close();
	}

	/**
	 * @see java.io.InputStream#mark(int)
	 */
	public void mark(int readlimit)
	{
		throw new RuntimeException("Not supported");
	}

	/**
	 * @see java.io.InputStream#markSupported()
	 */
	public boolean markSupported()
	{
		return false;
	}

	/**
	 * @see java.io.InputStream#read()
	 * @throws DataFormatException if there is a problem with the PGP data
	 * @throws IOException if an exception is thrown from the underyling stream
	 */
	public int read() throws DataFormatException, IOException
	{
		init();
		return in.read();
	}

	/**
	 * @see java.io.InputStream#read(byte[])
	 * @throws DataFormatException if there is a problem with the PGP data
	 * @throws IOException if an exception is thrown from the underyling stream
	 */
	public int read(byte[] b) throws DataFormatException, IOException
	{
		init();
		return in.read(b);
	}

	/**
	 * @see java.io.InputStream#read(byte[], int, int)
	 * @throws DataFormatException if there is a problem with the PGP data
	 * @throws IOException if an exception is thrown from the underyling stream
	 */
	public int read(byte[] b, int off, int len)
		throws DataFormatException, IOException
	{
		init();
		return in.read(b, off, len);
	}

	/**
	 * @see java.io.InputStream#reset()
	 * @throws DataFormatException if there is a problem with the PGP data
	 * @throws IOException if an exception is thrown from the underyling stream
	 */
	public void reset() throws DataFormatException, IOException
	{
		init();
		in.reset();
	}

	/**
	 * @see java.io.InputStream#skip(long)
	 * @throws DataFormatException if there is a problem with the PGP data
	 * @throws IOException if an exception is thrown from the underyling stream
	 */
	public long skip(long n) throws DataFormatException, IOException
	{
		init();
		return in.skip(n);
	}

	protected synchronized final void init()
		throws DataFormatException, IOException
	{
		if (inited || initing)
			return;
		initing = true;
		if (in instanceof PacketInputStream)
		{
			PacketInputStream pgpIn = (PacketInputStream) in;
			if (pgpIn.getType() != type)
			{
				throw new DataFormatException(
					"Wrong packet type; got "
						+ pgpIn.getType()
						+ "; expecting "
						+ type);
			}
		}
		engineInit();
		initing = false;
		inited = true;
	}

	protected abstract void engineInit()
		throws DataFormatException, IOException;
}