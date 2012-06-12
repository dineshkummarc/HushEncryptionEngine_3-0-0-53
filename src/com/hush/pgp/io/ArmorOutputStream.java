/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.pgp.io;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.util.Enumeration;
import java.util.Hashtable;

import com.hush.pgp.PgpConstants;
import com.hush.pgp.PgpUtils;
import com.hush.util.Base64;
import com.hush.util.Conversions;

/**
 * An OutputStream for creating PGP armor.
 */
public class ArmorOutputStream extends OutputStream implements PgpConstants
{

	private boolean opened = false;
	private boolean closed = false;
	private int type;
	private OutputStream outputStream;
	private long crc = ARMOR_CRC_INIT;
	private int rawHoldSize = 0;
	private byte[] rawHold = new byte[] { 0, 0 };
	private static final int LINE_LEN = 68;
	private int linePos = 0;
	private Hashtable headers = new Hashtable();

	private boolean inCleartext = true;

	public ArmorOutputStream(OutputStream outputStream, int type)
	{
		headers.put(ARMOR_HEADER_KEY_VERSION, VERSION);
		this.outputStream = outputStream;
		this.type = type;
	}

	/**
	 * Closes the stream, writing any final headers/footers.
	 * <br>
	 * Does not close the underlying stream.
	 * 
	 * @see java.io.OutputStream#close()
	 */
	public synchronized void close() throws IOException
	{
		if (closed)
			throw new IOException("Already closed");

		if (!opened)
			open();

		// First, clear out any leftover bytes.
		if (rawHoldSize != 0)
		{
			byte[] encoded = Base64.encode(rawHold, 0, rawHoldSize, false);
			int written = 0;
			while (written < encoded.length)
			{
				int amountToWrite =
					LINE_LEN - linePos < encoded.length - written
						? LINE_LEN - linePos
						: encoded.length - written;
				outputStream.write(encoded, written, amountToWrite);
				if ((linePos += amountToWrite) == LINE_LEN)
				{
					outputStream.write(CRLF);
					linePos = 0;
				}
				written += amountToWrite;
			}
		}
		outputStream.write(CRLF);

		outputStream.write((byte) '=');
		outputStream.write(Base64.encode(getChecksum()));

		switch (type)
		{
			case (ARMOR_TYPE_PGP_MESSAGE) :
				outputStream.write(ARMOR_FOOTER_PGP_MESSAGE);
				break;
			case (ARMOR_TYPE_PGP_SIGNED_MESSAGE) :
				outputStream.write(ARMOR_FOOTER_PGP_SIGNATURE);
				break;
			case (ARMOR_TYPE_PGP_SIGNATURE) :
				outputStream.write(ARMOR_FOOTER_PGP_SIGNATURE);
				break;
			case (ARMOR_TYPE_PGP_PUBLIC_KEY) :
				outputStream.write(ARMOR_FOOTER_PGP_PUBLIC_KEY);
				break;
			case (ARMOR_TYPE_PGP_PRIVATE_KEY) :
				outputStream.write(ARMOR_FOOTER_PGP_PRIVATE_KEY);
				break;
		}
		outputStream.write(CRLF);
		closed = true;
	}

	private byte[] getChecksum()
	{
		byte[] toReturn = new byte[3];

		toReturn[0] = (byte) ((crc & 0xff0000) >> 16);

		toReturn[1] = (byte) ((crc & 0x00ff00) >> 8);
		toReturn[2] = (byte) (crc & 0x0000ff);

		return toReturn;
	}

	private void open() throws IOException
	{
		switch (type)
		{
			case (ARMOR_TYPE_PGP_MESSAGE) :
				outputStream.write(ARMOR_HEADER_PGP_MESSAGE);
				break;
			case (ARMOR_TYPE_PGP_SIGNED_MESSAGE) :
				outputStream.write(ARMOR_HEADER_PGP_SIGNED_MESSAGE);
				break;
			case (ARMOR_TYPE_PGP_SIGNATURE) :
				outputStream.write(ARMOR_HEADER_PGP_SIGNATURE);
				break;
			case (ARMOR_TYPE_PGP_PUBLIC_KEY) :
				outputStream.write(ARMOR_HEADER_PGP_PUBLIC_KEY);
				break;
			case (ARMOR_TYPE_PGP_PRIVATE_KEY) :
				outputStream.write(ARMOR_HEADER_PGP_PRIVATE_KEY);
				break;
		}

		outputStream.write(CRLF);

		Enumeration e = headers.keys();

		while (e.hasMoreElements())
		{
			String key = (String) e.nextElement();
			outputStream.write(key.getBytes(UTF8));
			outputStream.write(": ".getBytes(UTF8));
			outputStream.write(((String) headers.get(key)).getBytes(UTF8));
			outputStream.write(CRLF);
		}

		outputStream.write(CRLF);
		opened = true;
	}

	private boolean onLineBeginning = true;

	/**
	 * Headers must be UTF-8.
	 * 
	 * @param key
	 * @param value
	 */
	public void setHeader(String key, String value)
	{
		if (opened)
			throw new IllegalStateException(
				"Cannot update header after data has "
					+ "already been written to the stream");
		headers.put(key, value);
	}

	/**
	 * Headers must be UTF-8.
	 * 
	 * @param headers
	 */
	public void setHeaders(Hashtable headers)
	{
		if (opened)
			throw new IllegalStateException(
				"Cannot update header after data has "
					+ "already been written to the stream");
		this.headers = headers;
	}

	public synchronized void write(byte[] in, int offset, int length)
		throws IOException
	{
		if (closed)
			throw new IOException("The stream has been closed");

		if (!opened)
			open();

		if (type == ARMOR_TYPE_PGP_SIGNED_MESSAGE && inCleartext)
		{
			for (int x = offset; x < offset + length; x++)
			{
				if (in[x] == 45 && onLineBeginning)
				{
					outputStream.write(45);
					outputStream.write(32);
				}
				onLineBeginning = (in[x] == 10);
				outputStream.write(new byte[] { in[x] });
			}
			return;
		}

		crc = PgpUtils.crc24(crc, in, offset, length);

		if (rawHoldSize + length < 3)
		{
			System.arraycopy(in, offset, rawHold, rawHoldSize, length);
			rawHoldSize = rawHoldSize + length;
			return;
		}

		int remainder = (rawHoldSize + length) % 3;

		byte[] encoded;

		if (rawHoldSize == 0)
		{
			encoded = Base64.encode(in, offset, length - remainder, false);
		}
		else
		{
			byte[] toEncode = new byte[rawHoldSize + length - remainder];
			System.arraycopy(rawHold, 0, toEncode, 0, rawHoldSize);
			System.arraycopy(
				in,
				offset,
				toEncode,
				rawHoldSize,
				length - remainder);
			encoded = Base64.encode(toEncode, 0, toEncode.length, false);
		}

		if (remainder > 0)
		{
			System.arraycopy(
				in,
				offset + length - remainder,
				rawHold,
				0,
				remainder);
			rawHoldSize = remainder;
		}
		else
		{
			rawHoldSize = 0;
		}

		int written = 0;
		while (written < encoded.length)
		{
			int amountToWrite =
				LINE_LEN - linePos < encoded.length - written
					? LINE_LEN - linePos
					: encoded.length - written;
			outputStream.write(encoded, written, amountToWrite);
			if ((linePos += amountToWrite) == LINE_LEN)
			{
				outputStream.write(CRLF);
				linePos = 0;
			}
			written += amountToWrite;
		}
	}

	public void write(byte[] b) throws IOException
	{
		write(b, 0, b.length);
	}

	public void write(int b) throws IOException
	{
		byte toWrite = (byte) ((b > 127) ? b - 256 : b);
		write(new byte[] { toWrite });
	}

	public void endCleartext() throws IOException
	{
		if (!onLineBeginning)
			outputStream.write(CRLF);
		outputStream.write(ARMOR_HEADER_PGP_SIGNATURE);
		outputStream.write(CRLF);
		outputStream.write(CRLF);
		inCleartext = false;
	}

	public String getCharacterEncoding()
	{
		Object val = headers.get(ARMOR_HEADER_KEY_CHARSET);
		if ( val == null ) return null;
		return (String)val;
	}
	
	public void setCharacterEncoding(String encoding)
		throws UnsupportedEncodingException
	{
		if ( encoding == null )
		{
			headers.remove(ARMOR_HEADER_KEY_CHARSET);
			return;
		}
		Conversions.checkCharacterEncoding(encoding);
		headers.put(ARMOR_HEADER_KEY_CHARSET, encoding);
	}

	public void setHash(int hashAlgorithm)
	{
		headers.put(ARMOR_HEADER_KEY_HASH, HASH_STRINGS[hashAlgorithm]);
	}
}