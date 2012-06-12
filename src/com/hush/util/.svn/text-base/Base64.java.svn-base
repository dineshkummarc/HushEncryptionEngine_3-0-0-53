/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.util;

/**
 * Used to decode and encode to/from Base64.
 *
 * @author   Erwin van der Koogh
 */
public class Base64
{
	/**
	 * The length to use for each line
	 */
	private final static int LINE_LENGTH = 64;
	private final static int LINE_LENGTHINC = LINE_LENGTH + 2;

	/**
	 * A static array that maps 6-bit integers to a specific char.
	 */
	private final static char[] enc_table =
		{
			'A',
			'B',
			'C',
			'D',
			'E',
			'F',
			'G',
			'H',
			'I',
			'J',
			'K',
			'L',
			'M',
			'N',
			'O',
			'P',
			'Q',
			'R',
			'S',
			'T',
			'U',
			'V',
			'W',
			'X',
			'Y',
			'Z',
			'a',
			'b',
			'c',
			'd',
			'e',
			'f',
			'g',
			'h',
			'i',
			'j',
			'k',
			'l',
			'm',
			'n',
			'o',
			'p',
			'q',
			'r',
			's',
			't',
			'u',
			'v',
			'w',
			'x',
			'y',
			'z',
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
			'+',
			'/' };

	/**
	 * A static array that maps ASCII code points to a 6-bit integer,
	 * or -1 for an invalid code point.
	 */
	private final static byte[] dec_table =
		{
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			62,
			-1,
			-1,
			-1,
			63,
			52,
			53,
			54,
			55,
			56,
			57,
			58,
			59,
			60,
			61,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			0,
			1,
			2,
			3,
			4,
			5,
			6,
			7,
			8,
			9,
			10,
			11,
			12,
			13,
			14,
			15,
			16,
			17,
			18,
			19,
			20,
			21,
			22,
			23,
			24,
			25,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			26,
			27,
			28,
			29,
			30,
			31,
			32,
			33,
			34,
			35,
			36,
			37,
			38,
			39,
			40,
			41,
			42,
			43,
			44,
			45,
			46,
			47,
			48,
			49,
			50,
			51,
			};

	/**
	 * Only static methods allowed
	 */
	private Base64()
	{
	}

	/**
	 * Decode the specified Base64 encoded bytes
	 *
	 * @param data the encoded bytes
	 * @return the decoded bytes
	 */
	public static byte[] decode(byte[] data)
	{
		int outlen = ((data.length) / 4) * 3;

		if (data[data.length - 2] == (byte) 0x3D) // 0x3D = '='
		{
			outlen -= 2;
		}
		else if (data[data.length - 1] == 0x3D)
		{
			outlen -= 1;
		}

		byte[] output = new byte[outlen];

		int i = 0;
		int j = 0;

		byte a;
		byte b;
		byte c;
		byte d;

		try
		{
			boolean atEnd = false;
			while (i < data.length)
			{
				while (data[i] >= 0 && data[i] < 33)
				{
					i++;
					if (i == data.length)
					{
						atEnd = true;
						break;
					}
				}
				if (atEnd == true)
				{
					break;
				}
				a = dec_table[data[i++]];
				b = dec_table[data[i++]];
				c = dec_table[data[i++]];
				d = dec_table[data[i++]];
				decode(output, j, a, b, c, d);
				j += 3;
			}
		}
		catch (ArrayIndexOutOfBoundsException aioobex)
		{
			throw new IllegalArgumentException("Length not multiple of 4");
		}

		return output;
	}

	/**
	 * Decode the specified Base64 encoded bytes
	 * 
	 * @param data the encoded bytes
	 * @param offset int
	 * @param a byte
	 * @param b byte
	 * @param c byte
	 * @param d byte
	 */
	public static void decode(
		byte[] data,
		int offset,
		byte a,
		byte b,
		byte c,
		byte d)
	{
		data[offset++] = (byte) ((a << 2) | (b >>> 4));

		if (c == -1)
		{
			return;
		}
		else
		{
			data[offset++] = (byte) ((b << 4) | (c >>> 2));
		}

		if (d == -1)
		{
			return;
		}
		else
		{
			data[offset++] = (byte) ((c << 6) | d);
		}
	}

	/**
	 * Decode the specified Base64 encoded String and return as a byte array
	 *
	 * @param str the encoded String
	 * @return the decoded bytes
	 */
	public static byte[] decode(String str)
	{
		if (str == null)
		{
			return null;
		}

		StringBuffer sb = new StringBuffer(str.length());
		int j = 0;
		int len = str.length();
		char c;

		for (int i = 0; i < len; i++)
		{
			c = str.charAt(i);

			if (isValidChar(c))
			{
				sb.append(c);
				j++;
			}
		}

		sb.setLength(j);

		return decode(sb.toString().trim().getBytes());
	}

	/**
	 * Encode the specified bytes
	 *
	 * @param data the bytes to be Base64 encoded
	 * @return the Base64 encoded bytes
	 */
	public static byte[] encode(byte[] data)
	{
		return encode(data, 0, data.length, true);
	}

	/**
	 * Encode the specified bytes
	 *
	 * @param data the bytes to be Base64 encoded
	 * @return the Base64 encoded bytes
	 */
	public static byte[] encode(
		byte[] data,
		int offset,
		int length,
		boolean lineBreaks)
	{
		byte a;
		byte b;
		byte c;

		if ((data == null) || (data.length < 1))
		{
			throw new IllegalArgumentException("Have to supply a real array");
		}

		// length of the total encoded string
		int len = ((length + 2) / 3) * 4;

		// length including the linebreaks.
		if (lineBreaks)
			len = len + ((len / LINE_LENGTH) * 2) + 2;

		byte[] output = new byte[len];

		int i = offset;
		int j = 0;

		int len2 = length - 3;

		while (i < offset + len2)
		{
			a = data[i++];
			b = data[i++];
			c = data[i++];

			output[j++] = (byte) (enc_table[(a >>> 2) & 0x3F]);
			output[j++] =
				(byte) (enc_table[((a << 4) & 0x30) + ((b >>> 4) & 0x0F)]);
			output[j++] =
				(byte) (enc_table[((b << 2) & 0x3C) + ((c >>> 6) & 0x03)]);
			output[j++] = (byte) (enc_table[c & 0x3F]);

			if (lineBreaks && ((j + 2) % LINE_LENGTHINC) == 0)
			{
				output[j++] = (byte) '\r';
				output[j++] = (byte) '\n';
			}

			if (lineBreaks && j == LINE_LENGTH)
			{
				output[j++] = (byte) '\r';
				output[j++] = (byte) '\n';
			}
		}

		int remain = length % 3;

		if (remain == 0)
		{
			a = data[i++];
			b = data[i++];
			c = data[i++];

			output[j++] = (byte) (enc_table[(a >>> 2) & 0x3F]);
			output[j++] =
				(byte) (enc_table[((a << 4) & 0x30) + ((b >>> 4) & 0x0F)]);
			output[j++] =
				(byte) (enc_table[((b << 2) & 0x3C) + ((c >>> 6) & 0x03)]);
			output[j++] = (byte) (enc_table[c & 0x3F]);
		}
		else if (remain == 1)
		{
			a = data[i++];
			output[j++] = (byte) enc_table[(a >>> 2 & 0x3F)];
			output[j++] = (byte) enc_table[(a << 4 & 0x30)];
			output[j++] = (byte) '=';
			output[j++] = (byte) '=';
		}
		else if (remain == 2)
		{
			a = data[i++];
			b = data[i++];
			output[j++] = (byte) enc_table[(a >>> 2 & 0x3F)];
			output[j++] =
				(byte) enc_table[((a << 4 & 0x30) + (b >>> 4 & 0x0F))];
			output[j++] = (byte) enc_table[(b << 2 & 0x3C)];
			output[j++] = (byte) '=';
		}

		if (lineBreaks && ((j + 2) % LINE_LENGTHINC) == 0)
		{
			output[j++] = (byte) '\r';
			output[j++] = (byte) '\n';
		}

		if (lineBreaks && j == LINE_LENGTH)
		{
			output[j++] = (byte) '\r';
			output[j++] = (byte) '\n';
		}

		if (lineBreaks)
		{
			output[j++] = (byte) '\r';
			output[j++] = (byte) '\n';
		}

		if (j != output.length)
		{
			throw new RuntimeException(
				"Bug in Base64. j != output.length: "
					+ j
					+ ", "
					+ output.length);
		}

		return output;
	}

	/**
	 * Used to check whether or not the specified character is valid in Base64 encoding
	 * 
	 * @return boolean indicating whether or not it is a valid character
	 * @param c the character to check
	 */
	public static boolean isValidChar(char c)
	{
		int i = (int) c;

		if ((i > 46) && (i < 59)) // between 0-9 and /
		{
			return true;
		}
		else if ((i > 64) && (i < 91)) //between A-Z
		{
			return true;
		}
		else if ((i > 96) && (i < 123)) //between a-z
		{
			return true;
		}
		else if (i == 43) //+
		{
			return true;
		}
		else if (i == 61) //=
		{
			return true;
		}
		else
		{
			return false;
		}
	}

}