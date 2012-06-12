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
import com.hush.util.Conversions;
import com.hush.util.Logger;

/**
 * A stream to read a PGP packet.
 *
 * @author Brian Smith
 *
 */
public class PacketInputStream extends InputStream implements PgpConstants
{

	/**
	 * Definition of the format of a PGP packet tag.  (RFC2440 4.2)
	 */
	public static final int OLD_TAG_FORMAT = 0;

	/**
	 * Definition of the format of a PGP packet tag.  (RFC2440 4.2)
	 */
	public static final int NEW_TAG_FORMAT = 1;

	private InputStream in;
	private boolean headerProcessed = false;
	private int type;
	private long totalLength;
	// Note, a length of -1 means an old format packet of indeterminent
	// length
	private long length;
	private boolean onLastSegment;
	private int tagFormat;

	/**
	 * Creates a <code>PacketInputStream</code> and saves the argument,
	 * the input stream <code>in</code> for later use.
	 * 
	 * @param in the underlying input stream
	 */
	public PacketInputStream(InputStream in)
	{
		this.in = in;
	}

	/* (non-Javadoc)
	 * @see java.io.InputStream#read()
	 * @throws DataFormatException if there is a problem with the PGP data
	 * @throws IOException if an exception is thrown from the underyling stream
	 */
	public int read() throws DataFormatException, IOException
	{
		byte[] b = new byte[1];
		int retVal = read(b, 0, 1);
		if (retVal == -1)
			return -1;
		else
			return Conversions.unsignedByteToInt(b[0]);
	}

	/* (non-Javadoc)
	 * @see java.io.InputStream#read(byte[])
	 * @throws DataFormatException if there is a problem with the PGP data
	 * @throws IOException if an exception is thrown from the underyling stream
	 */
	public int read(byte[] b) throws DataFormatException, IOException
	{
		return read(b, 0, b.length);
	}

	/* (non-Javadoc)
	 * @see java.io.InputStream#read(byte[], int, int)
	 * @throws DataFormatException if there is a problem with the PGP data
	 * @throws IOException if an exception is thrown from the underyling stream
	 */
	public int read(byte[] b, int off, int len)
		throws DataFormatException, IOException
	{
		// TODO: Fix up this method
		if (!headerProcessed)
			if (processHeader() == -1)
			{
				Logger.log(
					this,
					Logger.VERBOSE,
					"Got -1 while processing header");
				return -1;
			}

		int amountRead = 0;
		int amountStillNeeded = len;
		while (amountRead < len)
		{
			// If length is zero we either get the next segment
			// or return whatever has been read so far
			if (this.length == 0)
			{
				amountRead = (amountRead == 0) ? -1 : amountRead;
				break;
			}
			// The -1 length covers old format packets with length type
			// three that continue until EOF
			int amountToRead =
				(amountStillNeeded < this.length || this.length == -1)
					? amountStillNeeded
					: (int) this.length;
			int bytesReadThisTime = in.read(b, amountRead + off, amountToRead);

			if (bytesReadThisTime == -1)
			{
				if (this.length == -1)
				{
					amountRead = (amountRead == 0) ? -1 : amountRead;
					break;
				}
				else
					throw new DataFormatException("Unexpected EOF while reading packet");
			}
			if (this.length != -1)
				this.length -= bytesReadThisTime; //Will be zero

			amountRead += bytesReadThisTime;
			amountStillNeeded -= bytesReadThisTime;
			// If length is 0 read in the next segment, unless this
			// is the last segment
			if (this.length == 0 && !onLastSegment)
				getNewFormatLength();
		}

		/*
		if ( amountRead != -1 && Logger.getLogLevel() == Logger.VERBOSE )
		{
			FileOutputStream fs = new FileOutputStream(toString(), true);
			fs.write(b, off, amountRead);
			fs.close();
		}
		*/

		return amountRead;
	}

	/*
	
	
	public int read(byte[] b, int off, int len) throws IOException
	{
		if (!headerProcessed)
			if (processHeader() == -1)
				return -1;
	
		// A length of -1 means we keep reading until EOF.
		if (this.length == -1)
			return in.read(b, off, len);
	
		Logger.log(this, Logger.VERBOSE, "Remaining length: " + length);
		int amountRead = 0;
		int amountStillNeeded = len;
		while (amountRead < len)
		{
			// If length is zero we either get the next segment
			// or return whatever has been read so far
			if (this.length == 0)
			{
				int retVal = (amountRead == 0) ? -1 : amountRead;
				return retVal;
			}
			// The -1 length covers old format packets with length type
			// three that continue until EOF
			int amountToRead =
				(amountStillNeeded < this.length || this.length == -1)
					? amountStillNeeded
					: (int) this.length;
	
			int bytesReadThisTime = in.read(b, amountRead, amountToRead);
			if (bytesReadThisTime == -1)
			{
				int retVal = (amountRead == 0) ? -1 : amountRead;
				return retVal;
			}
	
			this.length -= bytesReadThisTime; //Will be zero
			amountRead += bytesReadThisTime;
			amountStillNeeded -= bytesReadThisTime;
			// If length is 0 read in the next segment, unless this
			// is the last segment
			if (this.length == 0 && !onLastSegment)
				getNewFormatLength();
		}
		return amountRead;
	}
	*/

	/* (non-Javadoc)
	 * @see java.io.InputStream#markSupported()
	 */
	public boolean markSupported()
	{
		return false;
	}

	/**
	 * Returns the total length of the packet.  Returns -1 if not known.
	 * or if EOF.
	 * 
	 * @return the total length or -1 if unknown or EOF
	 * @throws DataFormatException if there is a problem with the PGP data
	 * @throws IOException if an exception is thrown from the underyling stream
	 */
	public long getTotalLength() throws DataFormatException, IOException
	{
		if (!headerProcessed)
			if (processHeader() == -1)
				return -1;
		return totalLength;
	}

	/**
	 * Returns the remaining length of the packet.  Returns -1 if not known
	 * or if EOF.
	 * 
	 * @return the remaining length or -1 if unknown or EOF
	 * @throws DataFormatException if there is a problem with the PGP data
	 * @throws IOException if an exception is thrown from the underyling stream
	 */
	public long getLength() throws DataFormatException, IOException
	{
		if (!headerProcessed)
			if (processHeader() == -1)
				return -1;
		return length;
	}

	/**
	 * Returns the packet type.  May be any of the constants ending in
	 * <code>PacketTag</code> Will return -1 on EOF.
	 * 
	 * @return the packet type, or -1 on EOF
	 * @throws DataFormatException if there is a problem with the PGP data
	 * @throws IOException if an exception is thrown from the underyling stream
	 */
	public int getType() throws DataFormatException, IOException
	{
		if (!headerProcessed)
			if (processHeader() == -1)
				return -1;
		return type;
	}

	/**
	 * Returns the tag format. May be <code>OLD_TAG_FORMAT</code> or
	 * <code>theNewTagFormat</code>.  Returns -1 on EOF.
	 * See RFC2440 4.2.
	 * 
	 * @return the packet tag format, or -1 on EOF
	 * @throws DataFormatException if there is a problem with the PGP data
	 * @throws IOException if an exception is thrown from the underyling stream
	 */
	public int getTagFormat() throws DataFormatException, IOException
	{
		if (!headerProcessed)
			if (processHeader() == -1)
				return -1;
		return tagFormat;
	}

	/**
	 * This method can be used with old format packets in which
	 * the length is not specified in the tag, if you can determine the
	 * length from an external source.
	 * 
	 * @param length - the length of the packet contents
	 * @throws DataFormatException if there is a problem with the PGP data
	 * @throws IOException if an exception is thrown from the underyling stream
	 */
	public void setLength(long length)
	{
		Logger.log(this, Logger.DEBUG, "Set length to: " + length);
		this.length = length;
		onLastSegment = true;
	}

	private int processHeader() throws DataFormatException, IOException
	{
		if (headerProcessed)
			throw new IllegalStateException("Header already processed");
		int octet = in.read();

		if (octet == -1)
			return -1;

		if ((octet & 0x80) == 0)
			throw new DataFormatException(
				"First bit of first octet must be set; got " + octet);
		tagFormat = (octet & 0x40) >> 6;
		Logger.log(this, Logger.DEBUG, "Tag format: " + tagFormat);
		if (tagFormat == OLD_TAG_FORMAT)
			this.type = (octet & 0x3c) >> 2;
		else
			this.type = octet & 0x3f;
		Logger.log(this, Logger.DEBUG, "Tag type: " + type);
		if (tagFormat == OLD_TAG_FORMAT)
			getOldFormatLength(octet & 0x03);
		else
			getNewFormatLength();
		Logger.log(this, Logger.DEBUG, "Length: " + this.length);
		headerProcessed = true;
		return 0;
	}

	private void getOldFormatLength(int type)
		throws IOException, DataFormatException
	{
		onLastSegment = true;
		Logger.log(this, Logger.DEBUG, "Length type: " + type);
		byte[] lengthBytes;
		switch (type)
		{
			case 0 :
				this.length = in.read();

				break;
			case 1 :
				lengthBytes = new byte[2];
				if (in.read(lengthBytes) != 2)
					throw new DataFormatException("Unexpected EOF while reading two octet length");
				this.length = Conversions.bytesToLong(lengthBytes);
				break;
			case 2 :
				lengthBytes = new byte[4];
				if (in.read(lengthBytes) != 4)
					throw new DataFormatException("Unexpected EOF while reading four octet length");
				this.length = Conversions.bytesToLong(lengthBytes);
				break;
			case 3 :
				this.length = -1;
				break;
			default :
				throw new DataFormatException("Invalid length type");
		}
		this.totalLength = this.length;
		Logger.log(this, Logger.DEBUG, "Length: " + this.length);
	}

	private void getNewFormatLength() throws DataFormatException, IOException
	{
		// read the length
		int octet = in.read();

		if (octet == -1)
			throw new DataFormatException("Unexpected EOF while reading length header");
		if (octet < 192)
		{
			// length type 1
			Logger.log(this, Logger.DEBUG, "Length type: 1");
			this.length = octet;
			this.totalLength = this.length;
			onLastSegment = true;
		}
		else if (192 <= octet && octet <= 223)
		{
			// length type 2
			Logger.log(this, Logger.DEBUG, "Length type: 2");
			int octet2 = in.read();

			if (octet2 == -1)
				throw new DataFormatException(
					"Unexpected EOF while reading "
						+ "second octet in length header of type 2");
			this.length = ((octet - 192) << 8) + octet2 + 192;
			this.totalLength = this.length;
			onLastSegment = true;
		}
		else if (224 <= octet && octet <= 254)
		{
			// partial length
			Logger.log(this, Logger.VERBOSE, "Length type: partial");
			this.length = 1 << (octet & 0x1f);
			this.totalLength = -1;
			onLastSegment = false;
		}
		else
		{
			// length type 3
			Logger.log(this, Logger.DEBUG, "Length type: 3");
			byte[] octets = new byte[4];
			if (in.read(octets) != 4)
				throw new DataFormatException(
					"Unexpected EOF while reading "
						+ "length header of type 3");
			Logger.hexlog(
				this,
				Logger.DEBUG,
				"Octets for length type 3: ",
				octets);
			this.length = Conversions.bytesToLong(octets);
			this.totalLength = this.length;
			onLastSegment = true;
		}
		Logger.log(this, Logger.VERBOSE, "Length: " + this.length);
	}

}
