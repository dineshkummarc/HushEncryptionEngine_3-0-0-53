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
import java.io.OutputStream;

import com.hush.pgp.PgpConstants;
import com.hush.pgp.PgpUtils;
import com.hush.util.Logger;

/**
 * A stream to write out a PGP packet.
 * <br>
 * If partial lengths are used, at least the first 512 octets will be buffered,
 * as RFC2440 4.2.3 specifies that the first partial packet must be at
 * least that size.  After that, the specified buffer size will be used.
 * The default buffer size is 512.
 *
 * @author Brian Smith
 *
 */
public class PacketOutputStream extends OutputStream implements PgpConstants
{
	private OutputStream out;

	private int type;

	// A -1 length indicates that we are
	// this packet has no determined length.
	private long length = -2;

	private int totalWritten = 0;

	private boolean streamClosed = false;

	private boolean tagWritten = false;

	private boolean oldFormat;

	private byte[] encodedLength;

	private int bufferSize = 512;

	private ByteArrayOutputStream buffer;

	private boolean first512OctetsWritten = false;

	/**
	 * Creates a packet output stream. The type must be set before data
	 * is written to the stream. Wrapping this in a subclass of
	 * <code>packetContentOutputStream</code> will do that automatically.
	 *
	 * @param out the underlying output stream.
	 */
	public PacketOutputStream(OutputStream out)
	{
		this(out, false, 0);
	}

	/**
	 * Creates a packet output stream. The type must be set before data
	 * is written to the stream. Wrapping this in a subclass of
	 * <code>packetContentOutputStream</code> will do that automatically.
	 *
	 * @param out the underlying output stream.
	 * @param oldFormat if true, uses PGP 2.6.x packet formats.
	 */
	public PacketOutputStream(OutputStream out, boolean oldFormat)
	{
		this(out, oldFormat, 0);
	}

	/**
	 * Creates a packet output stream.
	 *
	 * @param out the underlying output stream.
	 * @param oldFormat if true, uses PGP 2.6.x packet formats.
	 * @param type the packet type.
	 * @see com.hush.pgp.PgpConstants
	 */
	public PacketOutputStream(OutputStream out, boolean oldFormat, int type)
	{
		this.out = out;
		this.type = type;
		this.oldFormat = oldFormat;
	}

	/**
	 * @see java.io.OutputStream#write(int)
	 */
	public void write(int b) throws IOException
	{
		this.write(new byte[] {(byte) b }, 0, 1);
	}

	/**
	 * @see java.io.OutputStream#write(byte[])
	 */
	public void write(byte[] b) throws IOException
	{
		this.write(b, 0, b.length);
	}

	/**
	 * @see java.io.OutputStream#write(byte[], int, int)
	 */
	public synchronized void write(byte[] b, int off, int len)
		throws IOException
	{
		if (streamClosed)
			throw new IOException("Stream closed");

		if (!tagWritten)
			writeTag();

		if (length == -1 && oldFormat)
		{
			out.write(b, off, len);
		}
		else if (length == -1)
		{
			if (!first512OctetsWritten || bufferSize != 0)
			{
				if (buffer == null)
					buffer = new ByteArrayOutputStream();
				buffer.write(b, off, len);
				int bufferSizeToUse =
					(first512OctetsWritten || bufferSize > 512)
						? bufferSize
						: 512;

				if (buffer.size() > bufferSizeToUse)
				{
					byte[] bufferBytes = buffer.toByteArray();

					buffer = new ByteArrayOutputStream();

					int amountWritten = 0;
					while (bufferBytes.length - amountWritten > bufferSize)
					{
						int writeThisCycle =
							encodePartialLength(
								bufferBytes.length - amountWritten);
						out.write(bufferBytes, amountWritten, writeThisCycle);
						amountWritten += writeThisCycle;
					}

					if (amountWritten - bufferBytes.length != 0)
						buffer.write(
							bufferBytes,
							amountWritten,
							bufferBytes.length - amountWritten);

					first512OctetsWritten = true;
				}
			}
			else
			{
				writeAsPartials(b, off, len);
			}
		}
		else
		{
			if (length > 0 && totalWritten + len > length)
			{
				throw new IOException(
					"A length of "
						+ length
						+ " was specified."
						+ " Can't write any more bytes.");
			}
			else
			{
				totalWritten += len;
			}
			out.write(b, off, len);
		}
	}

	/**
	 * @see java.io.OutputStream#close()
	 */
	public synchronized void close() throws IOException
	{
		Logger.log(this, Logger.DEBUG, "Closing stream");

		if (streamClosed)
			throw new IOException("Stream already closed");

		if (!tagWritten)
			writeTag();

		if (length == -1 && !oldFormat)
		{
			if (buffer.size() == 0)
			{
				out.write(0);
			}
			else
			{
				out.write(PgpUtils.encodeLength(buffer.size()));
				out.write(buffer.toByteArray());
			}
		}
		streamClosed = true;
	}

	/**
	 * Returns the expected length of the packet that will be generated.
	 * If we are dealing with partial lengths, this will return -1.
	 *
	 * @return the expected packet length.
	 */
	//TODO: remove
	/*
	public long getExpectedPacketLength()
	{
		if (length == -2)
			throw new IllegalStateException("Length not set");
		if (length == -1)
			return -1;
		return 1 + encodedLength.length + length;
	}
	*/

	/**
	 * Sets the type of the packet. Must be called before anything is
	 * written to the stream.
	 * 
	 * @param type the packet type.
	 * @see com.hush.pgp.PgpConstants
	 */
	public void setType(int type)
	{
		if (tagWritten)
			throw new IllegalStateException("Type cannot be set after tag is written");
		this.type = type;
	}

	/**
	 * Sets the length of the packet. Must be called before anything is
	 * written to the stream. Set to -1 if you want to use partial lengths
	 * in the case of a new format packet, or if you want the packet to 
	 * continue to EOF in the case of an old format packet.
	 * 
	 * @param length the packet length.
	 */
	public void setLength(long length)
	{
		if (tagWritten)
			throw new IllegalStateException("Length cannot be set after tag is written");
		this.length = length;
		if (length == -1)
			return;
		if (oldFormat)
			encodedLength = PgpUtils.encodeOldLength(length);
		else
			encodedLength = PgpUtils.encodeLength(length);
	}

	/**
	 * Sets the buffer size to use. This will be the minimum size of a partial
	 * packet.
	 * 
	 * @param bufferSize
	 */
	public void setBufferSize(int bufferSize)
	{
		this.bufferSize = bufferSize;
	}

	private void writeTag() throws IOException
	{
		if (length == -2)
			throw new IOException("Must set length first");
		if (oldFormat)
			writeOldTag();
		else
			writeNewTag();
	}

	/**
	 * If you don't know the length, use -1.
	 */
	private void writeNewTag() throws IOException
	{
		if (tagWritten)
			throw new IOException("Tag already written");
		int basePgp5ContentHeader = 3 << 6;
		out.write(basePgp5ContentHeader ^ type);
		if (length != -1)
		{
			out.write(encodedLength);
		}
		tagWritten = true;
	}

	/**
	 * If you don't know the length, use -1.
	 */
	private void writeOldTag() throws IOException
	{
		if (tagWritten)
			throw new IOException("Tag already written");
		int basePgp26ContentHeader = 2 << 6;
		out.write(basePgp26ContentHeader ^ (type << 2) ^ getLengthType(length));
		if (length != -1)
		{
			out.write(encodedLength);
		}
		tagWritten = true;
	}

	/**
	 * RFC2440 4.2.2.4
	 */
	private int encodePartialLength(long length) throws IOException
	{
		if (length <= 0)
			throw new IOException("Partial length must be positive");
		int exponent = 0;
		int value = 1;
		while (value * 2 < length)
		{
			++exponent;
			value *= 2;
		}

		int lengthHeader = (exponent ^ 0x1F) ^ 0xFF;

		int amountToWrite = 1;

		for (int x = 0; x < exponent; x++)
			amountToWrite *= 2;

		// Write the length header
		out.write(lengthHeader);

		return amountToWrite;
	}

	private int getLengthType(long length)
	{
		int lengthType;
		if (length == -1)
		{
			lengthType = 3;
		}
		else if ((length & 0xFFFF) != length)
		{
			lengthType = 2;
		}
		else if ((length & 0xFF) != length)
		{
			lengthType = 1;
		}
		else
		{
			lengthType = 0;
		}
		return lengthType;
	}

	private void writeAsPartials(byte[] b, int offset, int len)
		throws IOException
	{
		int amountWritten = 0;
		while (amountWritten < len)
		{
			int writeThisCycle = encodePartialLength(len - amountWritten);
			out.write(b, offset + amountWritten, writeThisCycle);
			amountWritten += writeThisCycle;
		}
	}
}
