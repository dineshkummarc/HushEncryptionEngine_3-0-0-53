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
import java.io.Serializable;

import com.hush.util.Conversions;
import com.hush.util.Logger;

/**
 * Implements a signature subpacket as described in
 * RFC 2440 5.2.3.1.
 *
 * @author Brian Smith
 */
public class SignatureSubpacket implements Serializable
{
	private static final long serialVersionUID = 7085504001069359989L;
	private byte[] data;
	private int type;
	private boolean critical;

	/**
	 * Signature sub-packet type definition.
	 */
	public static final byte TYPE_SIGNATURE_CREATION_TIME = 2;

	/**
	 * Signature sub-packet type definition.
	 */
	public static final byte TYPE_SIGNATURE_EXPIRATION_TIME = 3;

	/**
	 * Signature sub-packet type definition.
	 */
	public static final byte TYPE_EXPORTABLE_CERTIFICATION = 4;

	/**
	 * Signature sub-packet type definition.
	 */
	public static final byte TYPE_TRUST_SIGNATURE = 5;

	/**
	 * Signature sub-packet type definition.
	 */
	public static final byte TYPE_REGULAR_EXPRESSION = 6;

	/**
	 * Signature sub-packet type definition.
	 */
	public static final byte TYPE_REVOCABLE = 7;

	/**
	 * Signature sub-packet type definition.
	 */
	public static final byte TYPE_KEY_EXPIRATION_TIME = 9;

	/**
	 * Signature sub-packet type definition.
	 */
	public static final byte TYPE_PREFERRED_SYMMETRIC_ALGORITHMS = 11;

	/**
	 * Signature sub-packet type definition.
	 */
	public static final byte TYPE_REVOCATION_KEY = 12;

	/**
	 * Signature sub-packet type definition.
	 */
	public static final byte TYPE_ISSUER_KEY_ID = 16;

	/**
	 * Signature sub-packet type definition.
	 */
	public static final byte TYPE_NOTATION_DATA = 20;

	/**
	 * Signature sub-packet type definition.
	 */
	public static final byte TYPE_PREFERRED_HASH_ALGORITHMS = 21;

	/**
	 * Signature sub-packet type definition.
	 */
	public static final byte TYPE_PREFERRED_COMPRESSION_ALGORITHMS = 22;

	/**
	 * Signature sub-packet type definition.
	 */
	public static final byte TYPE_KEY_SERVER_PREFERENCES = 23;

	/**
	 * Signature sub-packet type definition.
	 */
	public static final byte TYPE_PREFERRED_KEY_SERVER = 24;

	/**
	 * Signature sub-packet type definition.
	 */
	public static final byte TYPE_PRIMARY_USER_ID = 25;

	/**
	 * Signature sub-packet type definition.
	 */
	public static final byte TYPE_POLICY_URL = 26;

	/**
	 * Signature sub-packet type definition.
	 */
	public static final byte TYPE_KEY_FLAGS = 27;

	/**
	 * Signature sub-packet type definition.
	 */
	public static final byte TYPE_SIGNERS_USER_ID = 28;

	/**
	 * Signature sub-packet type definition.
	 */
	public static final byte TYPE_REASON_FOR_REVOCATION = 29;

	/**
	 * Signature sub-packet type definition.
	 */
	public static final byte TYPE_FEATURES = 30;

	/**
	 * Signature sub-packet type definition.
	 */
	public static final byte TYPE_SIGNATURE_TARGET = 31;

	public SignatureSubpacket(int type, byte[] data, boolean critical)
	{
		this.type = type;
		this.data = data;
		this.critical = critical;
	}

	public byte[] getBytes()
	{
		int length = data.length + 1;
		byte[] encodedLength = PgpUtils.encodeLength(length);
		byte[] retBytes = new byte[encodedLength.length + length];
		System.arraycopy(encodedLength, 0, retBytes, 0, encodedLength.length);
		retBytes[encodedLength.length] =
			(byte) ((critical ? 0x80 : 0x00) | type);
		System.arraycopy(
			data,
			0,
			retBytes,
			encodedLength.length + 1,
			data.length);
		return retBytes;
	}

	public SignatureSubpacket(InputStream in) throws IOException
	{
		// read the length

		long length;

		int octet = in.read();
		if (octet == -1)
			throw new IOException("Unexpected EOF while reading length header");
		if (octet < 192)
		{
			// length type 1
			Logger.log(this, Logger.DEBUG, "Length type: 1");
			length = octet;
		}
		else if (192 <= octet && octet <= 255)
		{
			// length type 2
			Logger.log(this, Logger.DEBUG, "Length type: 2");
			int octet2 = in.read();
			if (octet2 == -1)
				throw new IOException("Unexpected EOF while reading second octet in length header of type 2");
			length = ((octet - 192) << 8) + octet2 + 192;
		}
		else
		{
			// length type 3
			Logger.log(this, Logger.DEBUG, "Length type: 3");
			byte[] octets = new byte[4];
			if (in.read(octets) != 4)
				throw new IOException("Unexpected EOF while reading length header of type 3");
			length = Conversions.bytesToLong(octets);
		}

		Logger.log(this, Logger.DEBUG, "Subpacket length: " + length);

		if ((type = in.read()) == -1)
			throw new IOException("Unexpected EOF while reading type");

		critical = (type & 0x80) > 0;

		type &= 0x7F;

		Logger.log(this, Logger.DEBUG, "Subpacket type: " + type);

		data = new byte[(int) length - 1];

		if (in.read(data) != data.length)
			throw new IOException("Unexpected EOF while reading subpacket contents");

		Logger.hexlog(this, Logger.DEBUG, "Subpacket data: ", data);
	}

	public byte[] getData()
	{
		return data;
	}

	public int getSubpacketSize()
	{
		return data.length + PgpUtils.encodeLength(data.length + 1).length + 1;
	}

	public int getType()
	{
		return type;
	}

	public boolean getCritical()
	{
		return critical;
	}
}