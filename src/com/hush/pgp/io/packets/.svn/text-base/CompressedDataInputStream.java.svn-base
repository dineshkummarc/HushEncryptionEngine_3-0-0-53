/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.pgp.io.packets;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

import com.hush.pgp.DataFormatException;
import com.hush.util.Logger;

/**
 * A stream to read PGP compressed data.
 *
 * @author Brian Smith
 *
 */
public class CompressedDataInputStream extends PacketContentInputStream
{
	private InflaterInputStream decompressedIn;

	/**
	 * Creates a <code>CompressedDataInputStream</code> and saves the argument,
	 * the input stream <code>in</code> for later use.  In most cases
	 * <code>in</code> should be a <code>PacketInputStream</code>.
	 * 
	 * @param in the underlying input stream.
	 */
	public CompressedDataInputStream(InputStream in)
	{
		super(in, PACKET_TAG_COMPRESSED_DATA);
	}

	/**
	 * @see java.io.InputStream#read()
	 * @throws DataFormatException if there is a problem with the PGP data
	 * @throws IOException if an exception is thrown from the underyling stream
	 */
	public int read() throws DataFormatException, IOException
	{
		init();
		try
		{
			int retVal = decompressedIn.read();
			return retVal;
		}
		catch (EOFException e)
		{
			return -1;
		}
	}

	/**
	 * @see java.io.InputStream#read(byte[])
	 * @throws DataFormatException if there is a problem with the PGP data
	 * @throws IOException if an exception is thrown from the underyling stream
	 */
	public int read(byte[] b) throws DataFormatException, IOException
	{
		return read(b, 0, b.length);
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
		try
		{
			int read = 0;	
			int length = len;
			// There is a bug in the deflator that does not always return the requested byte count 
			// even when there is enough bytes available and you need to ask for the requested bytes 
			// a few times.
			while (read != len) {
				int retVal = decompressedIn.read(b, off, length);
				if (retVal > 0) {
					read += retVal;
					off += retVal;
					length -= retVal;
				} else {
					return read > 0 ? read : -1;
				}
			}
			return read;
		}
		catch (EOFException e)
		{
			return -1;
		}
	}

	/**
	 * @see java.io.InputStream#close()
	 * @throws DataFormatException if there is a problem with the PGP data
	 * @throws IOException if an exception is thrown from the underyling stream
	 */
	public void close() throws DataFormatException, IOException
	{
		init();
		decompressedIn.close();
	}

	/**
	 * @throws DataFormatException if there is a problem with the PGP data
	 * @throws IOException if an exception is thrown from the underyling stream
	 */
	protected void engineInit() throws DataFormatException, IOException
	{
		int algorithm = super.read();
		Logger.log(this, Logger.DEBUG, "Compression algorithm: " + algorithm);
		switch (algorithm)
		{
			case -1 :
				throw new DataFormatException("Unexpected EOF while reading compression algorithm");
			case COMPRESSION_ALGORITHM_UNCOMPRESSED :
				throw new DataFormatException("No compression is not supported");
			case COMPRESSION_ALGORITHM_ZIP :
				decompressedIn =
					new InflaterInputStream(in, new Inflater(true));
				break;
			case COMPRESSION_ALGORITHM_ZLIB :
				decompressedIn =
					new InflaterInputStream(in, new Inflater(false));
				break;
			default :
				throw new DataFormatException(
					"Unknown compression algorithm: " + algorithm);
		}
	}
}