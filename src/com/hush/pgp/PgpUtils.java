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

import org.bouncycastle.crypto.Digest;

import com.hush.util.Conversions;

/**
 * Some common PGP related tasks.
 *
 * @author Brian Smith
 */
public class PgpUtils
{

	/**
	 * RFC 2440 4.2.2
	 */
	public static byte[] encodeLength(long length)
	{
		if (length < 0)
			throw new IllegalArgumentException("Length must be positive");
		byte[] encodedLength;
		if (length < 192)
		{
			// one octet length
			encodedLength = new byte[1];
			Conversions.longToBytes(length, encodedLength, 0, 1);
		}
		else if (length < 8384)
		{
			// two octet length
			encodedLength = new byte[2];
			long tempLength = length - 192;
			encodedLength[0] = (byte) ((tempLength >> 8) + 192);
			encodedLength[1] = (byte) (tempLength & 0xff);
			return encodedLength;
		}
		else
		{
			// five octet length
			encodedLength = new byte[5];
			encodedLength[0] = (byte) 0xFF;
			Conversions.longToBytes(length, encodedLength, 1, 4);
		}
		return encodedLength;
	}

	/**
	 * RFC 2440 4.2.1
	 */
	public static byte[] encodeOldLength(long length)
	{
		if (length < 0)
			throw new IllegalArgumentException("Length must be positive");
		byte[] encodedLength;
		if ((length & 0xFFFF) != length)
		{
			encodedLength = new byte[4];
		}
		else if ((length & 0xFF) != length)
		{
			encodedLength = new byte[2];
		}
		else
		{
			encodedLength = new byte[1];
		}
		Conversions.longToBytes(length, encodedLength, 0, encodedLength.length);
		return encodedLength;
	}

	public static byte[] checksumMod65536(byte[] b)
	{
		byte[] result = new byte[2];
		checksumMod65536(b, 0, b.length, result, 0);
		return result;
	}

	public static void checksumMod65536(
		byte[] in,
		int inOffset,
		int inLength,
		byte[] out,
		int outOffset)
	{
		int sum = 0;
		for (int x = 0; x < inLength; x++)
		{
			sum += Conversions.unsignedByteToInt(in[inOffset + x]);
			sum %= 65536;
		}
		out[outOffset] = (byte) ((sum & 0xFF00) >> 8);
		out[outOffset + 1] = (byte) (sum & 0xFF);
	}

	public static byte[] checksumSha1(byte[] b)
	{
		byte[] result =
			new byte[PgpConstants.HASH_LENGTHS[PgpConstants.HASH_SHA1]];
		checksumSha1(b, 0, b.length, result, 0);
		return result;
	}

	public static void checksumSha1(
		byte[] in,
		int inOffset,
		int inLength,
		byte[] out,
		int outOffset)
	{
		Digest digest = AlgorithmFactory.getDigest(PgpConstants.HASH_SHA1);
		digest.update(in, inOffset, in.length);
		digest.doFinal(out, outOffset);
	}

	public static long crc24(long crc, byte[] b, int offset, int len)
	{
		for (int j = offset; j < offset + len; j++)
		{
			crc ^= (b[j] << 16);

			for (int i = 0; i < 8; i++)
			{
				crc <<= 1;

				if ((crc & 0x1000000) != 0)
				{
					crc ^= PgpConstants.ARMOR_CRC_POLY;
				}
			}
		}
		return crc & 0xFFFFFFL;
	}

	/**
	 * Returns -1 if EOF.
	 */
	public static long getLength(InputStream in)
		throws DataFormatException, IOException
	{
		// read the length
		int octet = in.read();

		if (octet == -1)
			return -1;

		if (octet < 192)
		{
			return octet;
		}

		if (192 <= octet && octet <= 223)
		{
			// length type 2
			int octet2 = in.read();
			if (octet2 == -1)
				throw new DataFormatException(
					"Unexpected EOF while reading "
						+ "second octet in length header of type 2");
			return ((octet - 192) << 8) + octet2 + 192;
		}

		if (224 <= octet && octet <= 254)
		{
			return 1 << (octet & 0x1f);
		}

		// length type 3
		byte[] octets = new byte[4];
		if (in.read(octets) != 4)
			throw new DataFormatException(
				"Unexpected EOF while reading " + "length header of type 3");
		return Conversions.bytesToLong(octets);
	}
}