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
import com.hush.pgp.Key;
import com.hush.pgp.MPI;
import com.hush.util.Conversions;
import com.hush.util.Logger;

/**
 * A stream to read in a PGP public key.
 * <br>
 * The getters should be used to retrieve all information from this stream.
 * The standard <code>read</code> methods will just return EOF.
 * 
 * @author Brian Smith
 *
 */
public class PublicKeyInputStream extends PacketContentInputStream
{
	protected Key key = new Key();

	/**
	 * Creates a <code>PublicKeyInputStream</code> and saves the argument,
	 * the input stream <code>in</code> for later use.  In most cases
	 * <code>in</code> should be a <code>PacketInputStream</code>.
	 * 
	 * @param in the underlying input stream.
	 */
	public PublicKeyInputStream(InputStream in)
		throws DataFormatException, IOException
	{
		this(in, PACKET_TAG_PUBLIC_KEY);
	}

	protected PublicKeyInputStream(InputStream in, int packetTag)
	{
		super(in, packetTag);
	}

	/**
	 * Returns the key retrieved from the stream.
	 * 
	 * @throws DataFormatException if there is a problem with the PGP data
	 * @throws IOException if an exception is thrown from the underyling stream
	 * @return the key
	 */
	public Key getKey() throws DataFormatException, IOException
	{
		init();
		return key;
	}

	protected void engineInit() throws DataFormatException, IOException
	{
		int myByte;

		// Read in the version.
		myByte = read();

		Logger.log(this, Logger.DEBUG, "Version: " + myByte);

		if (myByte == -1)
			throw new DataFormatException("Unexpected EOF while reading version number");
		if (myByte != 2 && myByte != 3 && myByte != 4)
			throw new DataFormatException("Invalid version number");

		key.setVersion(myByte);

		// Read in the creation time, always 4 bytes
		byte[] creationTimeBytes = new byte[4];

		if (read(creationTimeBytes) != 4)
			throw new DataFormatException("Unexpected EOF while reading creation time");

		key.setCreationTime(Conversions.bytesToLong(creationTimeBytes));

		Logger.log(
			this,
			Logger.DEBUG,
			"Creation time: " + key.getCreationTime());

		if (key.getVersion() < 4)
		{
			byte[] validityPeriodBytes = new byte[2];
			if (read(validityPeriodBytes) != 2)
				throw new DataFormatException("Unexpected EOF while reading validity period");

			Logger.hexlog(
				this,
				Logger.DEBUG,
				"V3 validity period bytes: ",
				validityPeriodBytes);

			key.setValidityPeriod(
				(((int) validityPeriodBytes[0] << 8) | validityPeriodBytes[1])
					* 86400);

		}

		// Read in the algorithm ID
		if ((myByte = read()) == -1)
			throw new DataFormatException("Unexpected EOF while reading algorithm ID");

		Logger.log(this, Logger.DEBUG, "Algorithm: " + myByte);

		key.setAlgorithm(myByte);

		switch (key.getAlgorithm())
		{
			case CIPHER_RSA :
			case CIPHER_RSA_ENCRYPT_ONLY :
			case CIPHER_RSA_SIGN_ONLY :
				MPI publicModulus = new MPI(this, null, key.getVersion() == 4);
				key.setPublicKey(
					new MPI[] {
						publicModulus,
						new MPI(this, null, key.getVersion() == 4)});

				break;
			case CIPHER_DSA :
				key.setPublicKey(
					new MPI[] {
						new MPI(this, null, key.getVersion() == 4),
						new MPI(this, null, key.getVersion() == 4),
						new MPI(this, null, key.getVersion() == 4),
						new MPI(this, null, key.getVersion() == 4)});
				break;
			case CIPHER_ELGAMAL :
			case CIPHER_ELGAMAL_ENCRYPT_ONLY :
				key.setPublicKey(
					new MPI[] {
						new MPI(this, null, key.getVersion() == 4),
						new MPI(this, null, key.getVersion() == 4),
						new MPI(this, null, key.getVersion() == 4)});
				break;
			default :
				throw new DataFormatException(
					"Unsupported algorithm: " + key.getAlgorithm());
		}

		readSecretKeyMaterial();

	}

	protected void readSecretKeyMaterial()
		throws DataFormatException, IOException
	{
	}

}
