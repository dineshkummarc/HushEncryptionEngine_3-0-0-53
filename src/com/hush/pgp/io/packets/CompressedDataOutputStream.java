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
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

/**
 * A stream to write out PGP compressed data.
 *
 * @author Brian Smith
 */
public class CompressedDataOutputStream extends PacketContentOutputStream
{
	private OutputStream out;
	private OutputStream compressedStream;
	private int algorithm;
	private int level;

	/**
	 * Creates a <code>CompressedDataOutputStream</code>
	 * and saves the arguments for later use.  In most cases
	 * <code>out</code> should be a <code>PacketOutputStream</code>.
	 *
	 * @param out the underlying output stream.
	 * @param algorithm the compression algorithm to be used.
	 * @param level the level of compression to be used.
	 * @see com.hush.pgp.PgpConstants
	 * @see com.hush.pgp.io.packets.PacketOutputStream
	 */
	public CompressedDataOutputStream(
		OutputStream out,
		int algorithm,
		int level)
	{
		super(out, PACKET_TAG_COMPRESSED_DATA);
		this.algorithm = algorithm;
		this.level = level;
		this.out = out;
	}

	/**
	 * @see java.io.OutputStream#write(int)
	 */
	public void write(int b) throws IOException
	{
		init();
		compressedStream.write(b);
	}

	/**
	 * @see java.io.OutputStream#write(byte[])
	 */
	public void write(byte[] b) throws IOException
	{
		init();
		compressedStream.write(b, 0, b.length);
	}

	/**
	 * @see java.io.OutputStream#write(byte[], int, int)
	 */
	public void write(byte[] b, int off, int len) throws IOException
	{
		init();
		compressedStream.write(b, off, len);
	}

	/**
	 * @see java.io.OutputStream#close()
	 */
	public void close() throws IOException
	{
		init();
		if (out != compressedStream)
			compressedStream.close();
		else super.close();
	}

	protected void engineInit() throws IOException
	{
		super.write(algorithm);
		switch (algorithm)
		{
			case COMPRESSION_ALGORITHM_ZIP :
				compressedStream =
					new DeflaterOutputStream(out, new Deflater(level, true));
				break;
			case COMPRESSION_ALGORITHM_ZLIB :
				compressedStream =
					new DeflaterOutputStream(out, new Deflater(level, false));
				break;
			case COMPRESSION_ALGORITHM_UNCOMPRESSED :
				compressedStream = out;
				break;
			default :
				throw new IOException("Invalid algorithm: " + algorithm);
		}
	}
}
