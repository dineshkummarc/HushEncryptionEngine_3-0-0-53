/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.util;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;

/**
 * Miscellaneous data conversion routines.
 */
public class Conversions
{

	/**
	 * Constants required to perform hex-encoding of a byte array.
	 */
	private static final char[] hexArray =
		{
			'0',
			'1',
			'2',
			'3',
			'4',
			'5',
			'6',
			'7',
			'8',
			'9',
			'a',
			'b',
			'c',
			'd',
			'e',
			'f' };

	/**
	 * A lookup table for the high order hex character.
	 */
	private static final byte[] high = new byte[16];

	/**
	 * A lookup table for the low order hex character.
	 */
	private static final byte[] low = new byte[16];

	static {
		byte b;

		for (int i = 0; i < low.length; i++)
		{
			b = (byte) i;
			low[i] = (byte) (b & 0x0f);
		}

		for (int i = 0; i < high.length; i++)
		{
			b = (byte) i;
			high[i] = (byte) ((b << 4) & 0xf0);
		}
	}

	public static String bytesToHexString(byte[] inByteArray)
	{
		return bytesToHexString(inByteArray, 0, inByteArray.length);
	}

	/**
	 * Converts the given byte array into a hex string representation.
	 * 
	 * @param   b the array of bytes to convert to a hex string.
	 * @return  a hex String representation of the byte array.
	 */
	public static String bytesToHexString(byte[] b, int offset, int len)
	{
		if (b == null)
			return null;

		int position;
		StringBuffer returnBuffer = new StringBuffer();

		for (position = offset; position < len; position++)
		{
			returnBuffer.append(hexArray[((b[position] >> 4) & 0x0f)]);
			returnBuffer.append(hexArray[(b[position] & 0x0f)]);
		}

		return returnBuffer.toString();
	}

	/**
	 * This function accepts a number of bytes and returns a long
	 * integer.  Note that if the input is 8 bytes, and the high bit of the
	 * 0 byte is set, this will come out negative. 
	 *
	 * @param  b the byte array to convert to a long integer representation.
	 * @return a long integer representation of the byte array.
	 */
	public static long bytesToLong(byte[] b)
	{
		if (b.length > 8)
			throw new IllegalArgumentException("Must specify 8 bytes or less");

		long returnLong = 0;

		for (int n = 0; n < b.length; n++)
		{
			returnLong <<= 8;

			long aByte = b[n] < 0 ? b[n] + 256 : b[n];

			returnLong = returnLong | aByte;
		}

		return returnLong;
	}

	/**
	 * This function accepts a number of bytes and returns an
	 * integer.  Note that if the input is 4 bytes, and the high bit of the
	 * 0 byte is set, this will come out negative. 
	 *
	 * @param  bytes the byte array to convert to a long integer representation.
	 * @return a long integer representation of the byte array.
	 */
	public static int bytesToInt(byte[] b)
	{
		if (b.length > 4)
			throw new IllegalArgumentException("Must specify 4 bytes or less");

		int returnInt = 0;

		for (int n = 0; n < b.length; n++)
		{
			returnInt <<= 8;

			int aByte = b[n] < 0 ? b[n] + 256 : b[n];

			returnInt = returnInt | aByte;
		}

		return returnInt;
	}

	/**
	 * Returns the index for the given hex character in the byte array lookup array.
	 * This is used for both the hig order and low order hex characters.
	 *
	 * @param   c the character to get the lookup index.
	 * @return  an index into a byte array lookup table for the given hex character.
	 */
	private static int getIndex(char c)
	{
		if (('0' <= c) && (c <= '9'))
		{
			return ((byte) c - (byte) '0');
		}
		else if (('a' <= c) && (c <= 'f'))
		{
			return ((byte) c - (byte) 'a' + 10);
		}
		else if (('A' <= c) && (c <= 'F'))
		{
			return ((byte) c - (byte) 'A' + 10);
		}
		else
		{
			return -1;
		}
	}

	/**
	 * This method accepts a hex string and returns a byte array. The string must 
	 * represent an integer number of bytes.
	 *
	 * @param   str the hex string to convert to byte array representation.
	 * @return  the byte array representation of the hex string.
	 */
	public static byte[] hexStringToBytes(String str)
	{
		byte b;
		byte b2;
		int len = str.length();
		byte[] retval = new byte[len / 2];

		int j = 0;

		for (int i = 0; i < len; i += 2)
		{
			b = high[getIndex(str.charAt(i))];
			b2 = low[getIndex(str.charAt(i + 1))];
			retval[j++] = (byte) (b | b2);
		}

		return retval;
	}

	/**
	 * Converts a integer to a byte array representation.
	 *
	 * @param i the integer to convert to byte array representation.
	 * @return the byte array representation of the integer.
	 */
	public static byte[] intToBytes(int i)
	{
		int ii = i;

		byte[] returnBytes = new byte[8];

		for (int n = 3; n >= 0; n--)
		{
			returnBytes[n] = (byte) ii;
			ii = ii >>> 8;
		}

		return returnBytes;
	}

	/**
	 * Converts a long integer to a byte array representation.  If the target
	 * array is shorter than needed, the hi bytes of the integer will be
	 * truncated.
	 *
	 * @param l the long integer to convert to byte array representation.
	 * @param len the size of the byte array to return
	 * @return  the byte array representation of the long integer.
	 */
	public static byte[] longToBytes(long l, int len)
	{
		byte[] returnValue = new byte[len];
		longToBytes(l, returnValue, 0, len);
		return returnValue;
	}

	/**
	 * Converts a long integer to a byte array representation.  If the target
	 * array is shorter than needed, the hi bytes of the integer will be
	 * truncated.
	 *
	 * @param l the long integer to convert to byte array representation.
	 * @param len the size of the byte array to return
	 * @return the byte array representation of the long integer.
	 */
	public static void longToBytes(long l, byte[] b, int offset, int len)
	{
		int startPoint = len < 8 ? len - 1 : 7;

		if (startPoint < 7)
			l = l & (0xFFFFFFFFFFFFFFFFL >> (8 * (7 - startPoint)));

		for (int n = len - 1; n >= 0; n--)
		{
			b[offset + n] = (byte) l;
			l = l >> 8;
		}
	}

	/**
	 * Converts a byte in range -128 <= i <= 127 to an int in 
	 * range 0 <= i <= 255.
	 *
	 * @param b the byte to convert
	 * @return the converted integer
	 */
	public static int unsignedByteToInt(byte b)
	{
		return b < 0 ? (b + 256) : b;
	}

	/**
	 * Use if you don't want to have to catch a million
	 * UnsupportedEncodingExceptions.
	 * 
	 * @param in the string to convert to bytes
	 * @param encoding the encoding type
	 * @return the string encoded as a byte array
	 */
	public static byte[] stringToByteArray(String in, String encoding)
	{
		try
		{
			encoding = canonicalizeCharacterEncoding(encoding);
			return in.getBytes(encoding);
		}
		catch (UnsupportedEncodingException e)
		{
			throw new RuntimeException(
				"Character encoding not supported: " + encoding);
		}
	}

	/**
	 * Use if you don't want to have to catch a million
	 * UnsupportedEncodingExceptions.
	 * 
	 * @param in the byte array to convert to a string
	 * @param encoding the encoding type
	 * @return a string generated from the byte array
	 */
	public static String byteArrayToString(byte[] in, String encoding)
	{
		try
		{
			encoding = canonicalizeCharacterEncoding(encoding);
			return new String(in, encoding);
		}
		catch (UnsupportedEncodingException e)
		{
			throw new RuntimeException(
				"Character encoding not supported: " + encoding);
		}
	}

	/**
	 * Converts a BigInteger to a byte array, rejecting negative
	 * BigIntegers and discarding information about the sign.
	 * 
	 * @param b the BigInteger to convert to a byte array
	 * @return the BigInteger converted to a byte array
	 */
	public static byte[] bigIntegerToUnsignedBytes(BigInteger b)
	{
		// Convert the BigInteger to a byte array
		byte[] bytes = b.toByteArray();

		if (b.signum() == -1)
		{
			throw new IllegalArgumentException("Only taking positive BigIntegers");
		}

		while (bytes[0] == 0x00)
		{
			byte[] bytes2 = new byte[bytes.length - 1];
			System.arraycopy(bytes, 1, bytes2, 0, bytes2.length);
			bytes = bytes2;
		}

		return bytes;
	}

	public static void checkCharacterEncoding(String encoding)
			throws UnsupportedEncodingException
	{
		if ( encoding == null ) return;
		encoding = canonicalizeCharacterEncoding(encoding);
		"xyz".getBytes(encoding);
	}
	
	public static String canonicalizeCharacterEncoding(String encoding)
	{
		// Fix for old MSVM, which doesn't know UTF-8
		if (encoding.equalsIgnoreCase("UTF-8"))
			encoding = "UTF8";
		return encoding;
	}
}