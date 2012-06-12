/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.pgp;

import java.io.Serializable;

import com.hush.util.Conversions;

/**
 * A holder for notation data information as described in
 * RFC 2440 5.2.3.16.
 *
 * @author Brian Smith
 */
public class NotationData implements Serializable
{
	private static final long serialVersionUID = 6525002973481824839L;

	private static final int humanReadableFlag = 0x80;

	boolean humanReadable;
	byte[] name;
	byte[] value;

	public NotationData(byte[] data)
	{
		humanReadable = ((0x80 | data[0]) == data[0]);
		byte[] bytes = new byte[2];
		System.arraycopy(data, 4, bytes, 0, 2);
		name = new byte[Conversions.bytesToInt(bytes)];
		System.arraycopy(data, 6, bytes, 0, 2);
		value = new byte[Conversions.bytesToInt(bytes)];
		System.arraycopy(data, 8, name, 0, name.length);
		System.arraycopy(data, 8 + name.length, value, 0, value.length);
	}

	public NotationData(byte[] name, byte[] value, boolean humanReadable)
	{
		this.name = name;
		this.value = value;
		this.humanReadable = humanReadable;
	}

	public boolean getHumanReadable()
	{
		return humanReadable;
	}

	public byte[] getName()
	{
		return name;
	}

	public byte[] getValue()
	{
		return value;
	}

	public byte[] getBytes()
	{
		byte[] notationBytes = new byte[8 + name.length + value.length];
		if (humanReadable)
			notationBytes[0] |= humanReadableFlag;
		Conversions.longToBytes(name.length, notationBytes, 4, 2);
		Conversions.longToBytes(value.length, notationBytes, 6, 2);
		//System.arraycopy(Conversions.longToBytes(name.length, 2), 0,
		//	notationBytes, 4, 2);
		//System.arraycopy(Conversions.longToBytes(value.length, 2), 0,
		//	notationBytes, 6, 2);
		System.arraycopy(name, 0, notationBytes, 8, name.length);
		System.arraycopy(
			value,
			0,
			notationBytes,
			8 + name.length,
			value.length);
		return notationBytes;
	}

}
