/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.pgp.io;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.util.Hashtable;

import com.hush.pgp.DataFormatException;
import com.hush.pgp.PgpConstants;
import com.hush.pgp.PgpUtils;
import com.hush.util.ArrayTools;
import com.hush.util.Base64;
import com.hush.util.Conversions;
import com.hush.util.Logger;

/**
 * Interprets the ASCII wrapper of a PGP message.
 * If the message type is thePgpSignedMessage, -1 will be returned
 * after the plain text is read.  Upon resuming read, the signature bytes
 * will be read.  This means that a stream containing a PGP Signed Message has
 * EOF's.
 *
 * @author Brian Smith
 */
public class ArmorInputStream extends InputStream implements PgpConstants
{
	private InputStream inputStream;
	private int type;

	private long crc = ARMOR_CRC_INIT;

	// Bytes held for read method
	private byte[] decodedHold = new byte[0];
	boolean isEof = false;
	boolean inMessagePortionOfPgpSignedMessage = false;
	boolean checksumConfirmed = false;
	String characterEncoding = null;
	boolean inited = false;

	Hashtable headers = new Hashtable();

	public ArmorInputStream(InputStream in)
	{
		if (in == null)
		{
			throw new IllegalArgumentException("Null input stream");
		}
		this.inputStream = in;
	}

	public int available() throws IOException
	{
		throw new RuntimeException("Not implemented");
	}

	/**
	 * Closes the stream but not the underlying stream.
	 */
	public void close() throws IOException
	{
		while (read() != -1)
		{
		}
		//inputStream.close();
		inputStream = null;
		decodedHold = null;
	}

	private int engineReadDecodedHold(byte[] b, int offset, int length)
	{
		System.arraycopy(decodedHold, 0, b, offset, length);
		if (decodedHold.length > length)
		{
			byte[] newHold = new byte[decodedHold.length - length];
			System.arraycopy(decodedHold, 0, b, offset, length);
			System.arraycopy(decodedHold, length, newHold, 0, newHold.length);
			decodedHold = newHold;
		}
		else
			decodedHold = new byte[0];
		return length;
	}

	private byte[] queuedWhitespace = new byte[0];

	private int engineReadClearSigned(byte[] b, int offset, int length)
		throws DataFormatException, IOException
	{
		// If we already have the right number of bytes left over, just return them.
		if (decodedHold.length >= length)
		{
			return engineReadDecodedHold(b, offset, length);
		}

		ByteArrayOutputStream readBuffer = new ByteArrayOutputStream();

		if (decodedHold.length > 0)
		{
			readBuffer.write(decodedHold);
			decodedHold = new byte[0];
		}

		ByteArrayOutputStream lineStream;
		int x;
		boolean queuedLineFeed = false;
		boolean justOneMoreLine = false;
		while (true)
		{
			lineStream = new ByteArrayOutputStream();
			x = inputStream.read();
			while (true)
			{
				if (x == -1)
					throw new DataFormatException("Unexpected EOF");
				if (x == 10)
				{
					break;
				}
				if (x == 13)
				{
					if (queuedLineFeed)
						lineStream.write(13);
					queuedLineFeed = true;
				}
				else
				{
					if (queuedLineFeed)
					{
						lineStream.write(13);
						queuedLineFeed = false;
					}
					lineStream.write(x);
				}
				x = inputStream.read();
			}
			byte[] lineBytes = lineStream.toByteArray();
			if (lineBytes.length > 0 && lineBytes[0] == 45)
			{
				if (lineBytes.length < 3)
					throw new DataFormatException("Invalid unescaped dash in cleartext signature");
				if (ArrayTools
					.equals(
						ArrayTools.trim(lineBytes),
						ARMOR_HEADER_PGP_SIGNATURE))
				{
					isEof = true;
					readThroughHeaders();
					break;
				}
				if (lineBytes[1] != 20 || lineBytes[2] != 45)
					throw new DataFormatException("Invalid dash escape sequence in cleartext signature");
				byte[] unescapedLine = new byte[lineBytes.length - 2];
				System.arraycopy(
					lineBytes,
					2,
					unescapedLine,
					0,
					unescapedLine.length);
				readBuffer.write(queuedWhitespace);
				readBuffer.write(unescapedLine);
			}
			else
			{
				readBuffer.write(queuedWhitespace);
				readBuffer.write(lineBytes);
			}
			if (queuedLineFeed)
			{
				queuedWhitespace = new byte[] { 13, 10 };
				queuedLineFeed = false;
			}
			else
			{
				queuedWhitespace = new byte[] { 10 };
			}
			if (readBuffer.size() >= length)
			{
				// Always have to read one line ahead of what we need.
				// Otherwise, we might return the newline at the end
				// of the last line before the headers.
				if (justOneMoreLine)
				{
					break;
				}
				justOneMoreLine = true;
			}
		}
		byte[] decoded = readBuffer.toByteArray();
		return engineReadFinal(b, offset, length, decoded);
	}

	private int engineRead(byte[] b, int offset, int length)
		throws DataFormatException, IOException
	{
		// If we already have the right number of bytes left over, just return them.
		if (decodedHold.length >= length)
		{
			return engineReadDecodedHold(b, offset, length);
		}

		// If we have no bytes or not enough left over, 
		// start reading the b64 data and decode & return what is needed.
		else
		{
			int decodedNeeded = length - decodedHold.length;
			int spareDecoded =
				(decodedNeeded % 3 == 0) ? 0 : 3 - (decodedNeeded % 3);
			int encodedNeeded = ((decodedNeeded + spareDecoded) / 3) * 4;

			ByteArrayOutputStream encoded = new ByteArrayOutputStream();
			boolean onNewline = false;
			while (encoded.size() < encodedNeeded)
			{
				int thisByte = inputStream.read();
				if (thisByte == 61 && onNewline)
				{
					isEof = true;
					break;
				}
				if (thisByte == -1)
				{
					throw new DataFormatException("Unexpected EOF while reading ASCII armor");
				}
				else if (isWhitespace(thisByte))
				{
					onNewline = (thisByte == 10);
				}
				else
				{
					onNewline = false;
					encoded.write(thisByte);
				}
			}
			byte[] decoded =
				encoded.size() > 0
					? Base64.decode(encoded.toByteArray())
					: new byte[] {
			};

			return engineReadFinal(b, offset, length, decoded);
		}
	}

	private int engineReadFinal(
		byte[] b,
		int offset,
		int length,
		byte[] decoded)
	{
		// At this point we have 0 or more bytes in decodedHold
		// and some bytes in decoded.
		// These need to be copied into the buffer.
		int totalBytesAvailable = decoded.length + decodedHold.length;
		int bytesToCopyIntoBuffer =
			totalBytesAvailable > length ? length : totalBytesAvailable;

		// Copy the bytes in the decodedHold
		// There will never be more than length bytes in the decodedHold
		System.arraycopy(decodedHold, 0, b, offset, decodedHold.length);

		// Copy the newly decoded bytes
		System.arraycopy(
			decoded,
			0,
			b,
			offset + decodedHold.length,
			bytesToCopyIntoBuffer - decodedHold.length);

		// Update the decoded hold
		int extraBytes = totalBytesAvailable - bytesToCopyIntoBuffer;

		if (extraBytes > 0)
		{
			decodedHold = new byte[extraBytes];
			if (decodedHold.length > 0)
				System.arraycopy(
					decoded,
					decoded.length - extraBytes,
					decodedHold,
					0,
					extraBytes);
		}
		else
		{
			decodedHold = new byte[0];
		}
		return (bytesToCopyIntoBuffer == 0) ? -1 : bytesToCopyIntoBuffer;
	}

	private void init() throws IOException
	{
		if (inited)
			return;

		// First, skip any blank lines at the beginning.
		int x = 0;
		int previousChar = 10;
		while ((x = inputStream.read()) != 45)
		{
			if (x == -1)
				throw new DataFormatException("Found only whitespace.");
			if (!isWhitespace(x))
				throw new DataFormatException(
					"Encountered unexpected non-whitepace "
						+ "character before message header.");
			previousChar = x;
		}
		if (previousChar != 10)
			throw new DataFormatException("First '-' preceded by a character that is not a newline.");
		ByteArrayOutputStream headerStream = new ByteArrayOutputStream();
		headerStream.write('-');
		while ((x = inputStream.read()) != 10)
		{
			if (x == -1)
				throw new DataFormatException("Unexpected EOF before first header ended.");
			headerStream.write(x);
		}
		byte[] headerBytes = ArrayTools.trim(headerStream.toByteArray());

		//Use the header bytes to determine the type of message.
		if (ArrayTools.equals(headerBytes, ARMOR_HEADER_PGP_MESSAGE))
			type = ARMOR_TYPE_PGP_MESSAGE;
		else if (
			ArrayTools.equals(headerBytes, ARMOR_HEADER_PGP_SIGNED_MESSAGE))
		{
			inMessagePortionOfPgpSignedMessage = true;
			type = ARMOR_TYPE_PGP_SIGNED_MESSAGE;
		}
		else if (ArrayTools.equals(headerBytes, ARMOR_HEADER_PGP_SIGNATURE))
			type = ARMOR_TYPE_PGP_SIGNATURE;
		else if (ArrayTools.equals(headerBytes, ARMOR_HEADER_PGP_PUBLIC_KEY))
			type = ARMOR_TYPE_PGP_PUBLIC_KEY;
		else if (ArrayTools.equals(headerBytes, ARMOR_HEADER_PGP_PRIVATE_KEY))
			type = ARMOR_TYPE_PGP_PRIVATE_KEY;

		readThroughHeaders();

		inited = true;

		// At the end of this method, the stream is positioned at the beginning of
		// the content.
	}

	private void readThroughHeaders() throws IOException
	{
		// Read through the headers
		ByteArrayOutputStream headerStream;
		while (true)
		{
			headerStream = new ByteArrayOutputStream();
			int x;
			while ((x = inputStream.read()) != 10)
			{
				if (x == -1)
					throw new DataFormatException("Unexpected EOF before headers ended.");
				headerStream.write(x);
			}
			byte[] headerBytes = headerStream.toByteArray();
			if (ArrayTools.trim(headerBytes).length == 0)
				break;
			String header = Conversions.byteArrayToString(headerBytes, UTF8);
			int colonIndex = header.indexOf(":");
			if (colonIndex != -1)
			{
				String key = header.substring(0, colonIndex).trim();
				String value = header.substring(colonIndex + 1).trim();
				headers.put(key, value);
				if (ARMOR_HEADER_KEY_CHARSET.equalsIgnoreCase(key))
				{
					try
					{
						Conversions.checkCharacterEncoding(value);
						characterEncoding = value;
					}
					catch (UnsupportedEncodingException e)
					{
						Logger.log(
							this,
							Logger.ERROR,
							"Unsupported encoding " + value);
					}
				}
			}
		}
	}

	public int getType() throws IOException
	{
		init();
		return type;
	}

	public int read() throws IOException
	{
		byte[] ret = new byte[1];
		int bytesRead = read(ret, 0, 1);

		// This next bit returns -1 if we're on EOF, and
		// otherwise converts the byte ( -128 to 127 ) to
		// an int ( 0 to 255 ).  - sbs
		int result =
			(bytesRead == -1) ? -1 : Conversions.unsignedByteToInt(ret[0]);
		return result;
	}

	public int read(byte[] b) throws DataFormatException, IOException
	{
		return read(b, 0, b.length);
	}

	public int read(byte[] b, int off, int len)
		throws DataFormatException, IOException
	{
		init();
		int retVal;
		if (b == null)
			throw new NullPointerException();
		if (off < 0 || len < 0 || off + len > b.length)
			throw new IndexOutOfBoundsException();
		if (isEof)
		{
			if (decodedHold.length > 0)
			{
				retVal = engineReadDecodedHold(b, off, len);
			}
			else if (inMessagePortionOfPgpSignedMessage)
			{
				inMessagePortionOfPgpSignedMessage = false;
				isEof = false;
				retVal = -1;
			}
			else
			{
				retVal = -1;
			}
		}
		else if (
			type == ARMOR_TYPE_PGP_SIGNED_MESSAGE
				&& inMessagePortionOfPgpSignedMessage)
		{
			retVal = engineReadClearSigned(b, off, len);
		}
		else
		{
			retVal = engineRead(b, off, len);
		}
		if (retVal == -1 && isEof)
			checkChecksum();

		if (retVal != -1 && !inMessagePortionOfPgpSignedMessage)
		{
			crc = PgpUtils.crc24(crc, b, off, retVal);
		}
		return retVal;
	}

	/**
	 * Returns the character encoding, which is UTF-8 by default.
	 */
	public String getCharacterEncoding() throws IOException
	{
		init();
		return characterEncoding;
	}

	/**
	 * Returns a header.
	 */
	public String getHeader(String key) throws IOException
	{
		init();
		return (String) headers.get(key);
	}

	private void checkChecksum() throws IOException
	{
		if (checksumConfirmed)
			return;
		checksumConfirmed = true;
		byte[] checksumBuffer = new byte[4];
		if (inputStream.read(checksumBuffer) != 4)
			throw new DataFormatException("Incomplete ASCII armor checksum");
		byte[] checksumBytes = Base64.decode(checksumBuffer);
		if (Conversions.bytesToLong(checksumBytes) != crc)
		{
			throw new DataFormatException("ASCII armor checksum failed");
		}
	}

	private static boolean isWhitespace(int b)
	{
		return b < 33 || b == 127;
	}

}