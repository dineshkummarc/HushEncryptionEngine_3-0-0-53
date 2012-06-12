/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.pgp;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.util.Vector;

import com.hush.util.Conversions;
import com.hush.util.Logger;

/**
 * Class MPI representing a 'Multi Precision Integer' (MPI) as
 * specified in rfc2440. It uses the <code>java.math.BigInteger</code>
 * class for the actual calculations.
 * 
 * @author Magnus Hessel
 */
public class MPI implements Serializable
{
	private static final long serialVersionUID = 8260097712071203150L;

	private BigInteger myBigInteger;

	/**
	 * Construction of an MPI from a byte array.
	 *
	 * @param mpiRaw the byte[] from which the MPI will be read
	 * @param offset the starting point in the array
	 */
	public MPI(byte[] mpiRaw, int offset)
	{
		int bitLength =
			(Conversions.unsignedByteToInt(mpiRaw[offset]) << 8)
				| Conversions.unsignedByteToInt(mpiRaw[offset + 1]);

		int mpiDataLength = (bitLength + 7) / 8;
		if (mpiRaw.length - (offset + 2) < mpiDataLength)
			throw new IllegalArgumentException("Not enough bytes for MPI");
		;
		Logger.log(this, Logger.DEBUG, "MPI bit length: " + bitLength);
		Logger.log(
			this,
			Logger.DEBUG,
			"MPI total length in bytes: " + (mpiDataLength + 2));

		byte[] realBytes = new byte[mpiDataLength];
		System.arraycopy(mpiRaw, offset + 2, realBytes, 0, realBytes.length);
		myBigInteger = new BigInteger(1, realBytes);
	}

	/**
	 * Construction of an MPI from an InputStream.
	 *
	 * @param in the stream from which the MPI will be read
	 */
	public MPI(InputStream in) throws IOException
	{
		this(in, null, false);
	}

	/**
	 * Construction of an MPI from an InputStream.
	 *
	 * @param in the stream from which the MPI will be read
	 * @param out MPI data read will also be written here
	 * @param includeLengthInOut write two octet length to out as well
	 */
	public MPI(InputStream in, OutputStream out, boolean includeLengthInOut)
		throws IOException
	{
		byte[] twoBytes = new byte[2];

		if (in.read(twoBytes) != 2)
			throw new IOException("Unexpected EOF while reading MPI length");

		if (out != null && includeLengthInOut)
			out.write(twoBytes);

		int bitLength =
			(Conversions.unsignedByteToInt(twoBytes[0]) << 8)
				| Conversions.unsignedByteToInt(twoBytes[1]);

		byte[] realBytes = new byte[(bitLength + 7) / 8];

		Logger.log(this, Logger.DEBUG, "MPI bit length: " + bitLength);
		Logger.log(
			this,
			Logger.DEBUG,
			"MPI total length in bytes: " + (realBytes.length + 2));

		if (in.read(realBytes) != realBytes.length)
			throw new IOException("Unexpected EOF while reading MPI");

		if (out != null)
			out.write(realBytes);

		myBigInteger = new BigInteger(1, realBytes);
	}

	/**
	 * Construction of an MPI from a BigInteger.
	 *
	 * @param bigInt the integer from which the MPI will be created
	 */
	public MPI(BigInteger bigInt)
	{
		if (bigInt == null)
		{
			throw new NullPointerException("Null values for integer in not allowed");
		}
		myBigInteger = bigInt;
	}

	/**
	 * Get a <code>java.math.BigInteger</code> object for integer calculations.
	 * <p>
	 * @return the integer contained in this MPI
	 */
	public BigInteger getBigInteger()
	{
		return myBigInteger;
	}

	/**
	 * Retrieve the length of the seriazlied representaions of this
	 * MPI (if serialized) will have.
	 *
	 * @return the length of the serialized representation
	 */
	public int getLength()
	{
		return ((myBigInteger.bitLength() + 7) / 8) + 2;
	}

	/**
	 * Get the serialization of this MPI object. 
	 *
	 * @return the serialized representation of the MPI
	 */
	public byte[] getRaw()
	{
		int bitLength = myBigInteger.bitLength();
		byte[] result = new byte[getLength()];
		result[0] = (byte) (bitLength >> 8);
		result[1] = (byte) (bitLength & 0xFF);

		byte[] bigIntegerRepr = myBigInteger.toByteArray();
		int offset = 0;

		if (bigIntegerRepr.length != (result.length - 2))
		{
			offset = bigIntegerRepr.length - (result.length - 2);
		}
		System.arraycopy(bigIntegerRepr, offset, result, 2, result.length - 2);
		return result;
	}

	/**
	 * Conversion from an array of MPI objects to its binary representation.
	 *
	 * @return a byte array containing the MPI's
	 * @param mpis the MPI's to convert to bytes
	 */
	public static byte[] mpis2Bytes(MPI[] mpis)
	{
		int length = 0;

		for (int i = 0; i < mpis.length; i++)
			length += mpis[i].getLength();

		byte[] toReturn = new byte[length];
		int offset = 0;

		for (int i = 0; i < mpis.length; i++)
		{
			byte[] raw = mpis[i].getRaw();
			System.arraycopy(raw, 0, toReturn, offset, raw.length);
			offset += raw.length;
		}

		return toReturn;
	}

	/**
	 * Creation of an array of MPI objects from its binary representation.
	 *
	 * @return the resulting array of MPI's
	 * @param data raw representation of MPI's
	 * @param offset starting point for reading the MPI's
	 * @param len the point in the array to stop reading.
	 */
	public static MPI[] parseAllMPIs(byte[] data, int offset, int len)
	{
		Vector resultVector = new Vector();

		try
		{

			while (offset < len)
			{
				MPI mpi = new MPI(data, offset);
				resultVector.addElement(mpi);
				offset += mpi.getLength();
			}

		}
		catch (IllegalArgumentException e)
		{
			// We have read all the available MPI's
		}

		MPI[] result = new MPI[resultVector.size()];
		resultVector.copyInto(result);

		return result;
	}

	/**
	 * Creation of an array of MPI objects from its binary representation. The buffer
	 * could contain arbitrarily many MPI.
	 *
	 * @param in the stream from which to read the MPI's
	 * @return the resulting array of MPI's
	 */
	public static MPI[] parseAllMPIs(InputStream in) throws IOException
	{
		Vector resultVector = new Vector();
		while (in.available() > 0)
		{
			MPI mpi = new MPI(in);
			resultVector.addElement(mpi);
		}
		MPI[] result = new MPI[resultVector.size()];
		resultVector.copyInto(result);
		return result;
	}

	/**
	 * Creation of a specified number of MPI's from a stream.
	 *
	 * @return the resulting array of MPI's
	 * @param in a stream from which to read the MPI's
	 * @param numberOfMpis number of MPI's to read
	 */
	public static MPI[] parseMPIs(InputStream in, int numberOfMpis)
		throws IOException
	{
		MPI[] result = new MPI[numberOfMpis];

		for (int i = 0; i < numberOfMpis; i++)
		{
			result[i] = new MPI(in);
		}

		return result;
	}
}