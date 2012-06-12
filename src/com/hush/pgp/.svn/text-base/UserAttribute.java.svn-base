/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.pgp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Vector;

import com.hush.util.Conversions;
import com.hush.util.ExceptionWrapper;

/**
 * A class that encapsulates a PGP user Attribute.
 * 
 * @author Brian Smith 
 */
public class UserAttribute extends Signable
{
	private static final long serialVersionUID = -1598637352689787891L;

	byte[] content;

	Vector subpacketTypes = new Vector();
	Vector subpackets = new Vector();

	public void addSubpacket(int type, byte[] contents)
	{
		content = null;
		subpacketTypes.addElement(new Integer(type));
		subpackets.addElement(contents);
	}

	public byte[] getBytes()
	{
		try
		{
			if (content != null)
				return content;
			ByteArrayOutputStream data = new ByteArrayOutputStream();
			for (int x = 0; x < subpackets.size(); x++)
			{
				byte[] subpacketBytes = (byte[]) subpackets.elementAt(x);
				data.write(PgpUtils.encodeLength(subpacketBytes.length + 1));
				data.write(((Integer) subpacketTypes.elementAt(x)).intValue());
				data.write(subpacketBytes);
			}
			return data.toByteArray();
		}
		catch (IOException e)
		{
			throw ExceptionWrapper.wrapInRuntimeException("Should never happen", e);
		}
	}

	public byte[] getBytesForSignature(int signatureVersion)
	{
		if (signatureVersion < 4)
			return getBytes();
		byte[] bytes = getBytes();
		byte[] signableBytes = new byte[5 + bytes.length];
		signableBytes[0] = (byte) 0xd1;
		Conversions.longToBytes(bytes.length, signableBytes, 1, 4);
		System.arraycopy(bytes, 0, signableBytes, 5, bytes.length);
		return signableBytes;
	}

	/**
	 * This method verifies all the signatures on the user attribute packet by the
	 * given key, and returns all the signatures that verify successfully.
	 * It also checks for revocation signatures, for the given date.
	 * <br>
	 * The array of signatures can then be parsed for information regarding
	 * the verified certification.
	 * 
	 * @param key the signing key
	 * @param time check for validity at this time, in seconds since 1970-01-01 00:00:00; -1 indicates ignore
	 * @return all the signatures that successfully verify
	 */
	public Signature[] verifyCertifications(
		Key key,
		long time,
		boolean dieOnFailure)
		throws InvalidSignatureException
	{
		Signature[] returnValue =
			verifySignatures(
				key,
				new int[] {
					Signature.SIGNATURE_ON_BINARY_DOCUMENT,
					Signature.SIGNATURE_ON_CANONICAL_TEXT,
					Signature.SIGNATURE_STANDALONE,
					Signature.SIGNATURE_CERTIFICATION_GENERIC,
					Signature.SIGNATURE_CERTIFICATION_PERSONA,
					Signature.SIGNATURE_CERTIFICATION_CASUAL,
					Signature.SIGNATURE_CERTIFICATION_POSITIVE },
				time,
				dieOnFailure);
		return returnValue;
	}

	public void setContent(byte[] content) throws DataFormatException
	{
		try
		{
			this.content = content;
			ByteArrayInputStream contentStream =
				new ByteArrayInputStream(content);
			long x;
			while ((x = PgpUtils.getLength(contentStream)) != -1)
			{
				int type = contentStream.read();
				byte[] subpacket = new byte[(int) x - 1];
				int amountRead = 0;
				while (amountRead < subpacket.length)
				{
					amountRead += contentStream.read(subpacket);
					if (amountRead == -1)
						throw new DataFormatException("Unexpected EOF while reading user attribute subpacket contents");
				}
				subpacketTypes.addElement(new Integer(type));
				subpackets.addElement(subpacket);
			}
		}
		catch (IOException e)
		{
			if (e instanceof DataFormatException)
				throw (DataFormatException) e;
			throw ExceptionWrapper.wrapInRuntimeException("Error reading user attribute content",
					e);
		}
	}
}
