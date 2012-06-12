/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.pgp.io.packets;

import java.io.IOException;
import java.io.OutputStream;

import com.hush.pgp.MPI;
import com.hush.pgp.Signature;
import com.hush.pgp.SignatureSubpacket;
import com.hush.util.Conversions;
import com.hush.util.Logger;

/**
 * A stream to write out a PGP signature.
 * <br>
 * Based on RFC2440 5.2.
 * <br>
 * The <code>write</code> methods on this stream will fail because all the
 * necessary data is specified in the constructor. This stream should just
 * be constructed and closed. All data will be written to the underlying
 * output stream on close.
 * 
 * @author Brian Smith
 *
 */
public class SignatureOutputStream extends PacketContentOutputStream
{
	private Signature signature;

	/**
	 * Creates a <code>SignatureOutputStream</code> and saves the arguments
	 * for later use.  In most cases, <code>out</code> should be a 
	 * PacketOutputStream.
	 * 
	 * @param out the underlying output stream.
	 * @param signature the signature to write to the underlying stream.
	 * @see com.hush.pgp.io.packets.PacketOutputStream
	 * @see com.hush.pgp.Signature
	 */
	public SignatureOutputStream(OutputStream out, Signature signature)
	{
		super(out, PACKET_TAG_SIGNATURE);
		this.signature = signature;
		setLength(calculateLength());
	}

	/**
	 * Returns the underlying <code>Signature</code> object of this stream.
	 * 
	 * @return the underlying signature.
	 */
	public Signature getSignature()
	{
		return signature;
	}

	protected void engineInit() throws IOException
	{
		Logger.log(this, Logger.DEBUG, "Version: " + signature.getVersion());

		write(signature.getVersion());

		if (signature.getVersion() < 4)
			initVersion3();
		else
			initVersion4();

		finalInit();

		signature = null;
	}

	private void initVersion3() throws IOException
	{
		// write length of 5
		write(5);

		write(signature.getSignatureType());

		byte[] creationTimeBytes = new byte[4];

		Conversions.longToBytes(
			signature.getCreationTime(false),
			creationTimeBytes,
			0,
			4);

		write(creationTimeBytes);

		write(signature.getIssuerKeyID(false));

		Logger.hexlog(
			this,
			Logger.DEBUG,
			"Key ID: ",
			signature.getIssuerKeyID(false));

		write(signature.getPublicKeyAlgorithm());

		write(signature.getHashAlgorithm());
	}

	private void initVersion4() throws IOException
	{
		write(signature.getSignatureType());

		write(signature.getPublicKeyAlgorithm());

		write(signature.getHashAlgorithm());

		SignatureSubpacket[] hashedSubpackets = signature.getHashedSubpackets();

		SignatureSubpacket[] unhashedSubpackets =
			signature.getUnhashedSubpackets();

		int hashedSubpacketLength = 0;
		int unhashedSubpacketLength = 0;

		for (int x = 0; x < hashedSubpackets.length; x++)
			hashedSubpacketLength += hashedSubpackets[x].getSubpacketSize();

		for (int x = 0; x < unhashedSubpackets.length; x++)
			unhashedSubpacketLength += unhashedSubpackets[x].getSubpacketSize();

		byte[] hashedSubpacketLengthBytes = new byte[2];

		Conversions.longToBytes(
			hashedSubpacketLength,
			hashedSubpacketLengthBytes,
			0,
			2);
		write(hashedSubpacketLengthBytes);

		for (int x = 0; x < hashedSubpackets.length; x++)
		{
			write(hashedSubpackets[x].getBytes());
		}

		byte[] unhashedSubpacketLengthBytes = new byte[2];

		Conversions.longToBytes(
			unhashedSubpacketLength,
			unhashedSubpacketLengthBytes,
			0,
			2);
		write(unhashedSubpacketLengthBytes);

		for (int x = 0; x < unhashedSubpackets.length; x++)
		{
			write(unhashedSubpackets[x].getBytes());
		}
	}

	private void finalInit() throws IOException
	{
		write(signature.getLeftSixteenBitsOfHash());

		MPI[] mpis = signature.getSignatureMPIs();
		int x;
		for (x = 0; x < mpis.length; x++)
		{
			write(mpis[x].getRaw());
		}
	}

	private int calculateLength()
	{
		int length;
		if (signature.getVersion() < 4)
		{
			length = 19;
		}
		else
		{
			length = 10;

			SignatureSubpacket[] hashedSubpackets =
				signature.getHashedSubpackets();
			for (int x = 0; x < hashedSubpackets.length; x++)
				length += hashedSubpackets[x].getSubpacketSize();

			SignatureSubpacket[] unhashedSubpackets =
				signature.getUnhashedSubpackets();
			for (int x = 0; x < unhashedSubpackets.length; x++)
				length += unhashedSubpackets[x].getSubpacketSize();

			// Creation time is mandatory, so if it hasn't been set,
			// add 6 bytes to accomodate it.
			if (signature.getCreationTime(false) == -1)
				length += 6;
		}
		length += calculateMPILength();
		return length;
	}

	private long calculateMPILength()
	{
		MPI[] mpis = signature.getSignatureMPIs();
		long length = 0;
		int thisMPILength;
		if (mpis == null)
			throw new IllegalStateException("The signature MPI's are null, "
					+ "which may mean that the finishVerification or "
					+ "finishSigning operation was never called. If "
					+ "you are using a PGP stream, you probably should close it.");
		for (int x = 0; x < mpis.length; x++)
		{
			thisMPILength = mpis[x].getRaw().length;
			Logger.log(
				this,
				Logger.DEBUG,
				"Signature MPI of length: " + thisMPILength);
			length += thisMPILength;
		}
		return length;
	}

}