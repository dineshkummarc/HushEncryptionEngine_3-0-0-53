/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.pgp.io.packets;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import com.hush.pgp.DataFormatException;
import com.hush.pgp.S2kAlgorithm;

/**
 * A stream to read in a PGP symmetric key encrypted session key.
 * <br>
 * The getters should be used to retrieve all information from this stream.
 * The standard <code>read</code> methods will just return EOF.
 * 
 * @author Brian Smith
 *
 */
public class SymmetricKeyEncryptedSessionKeyInputStream
	extends PacketContentInputStream
{
	private int algorithm;
	private S2kAlgorithm s2k;
	private byte[] encryptedSessionKey = null;

	/**
	 * Creates a 
	 * <code>SymmetricallyEncryptedSessionKeyInputStream</code>
	 * and saves the argument, the input stream <code>in</code> for later use.
	 * In most cases <code>in</code> should be a
	 * <code>PacketInputStream</code>.
	 * 
	 * @param in the underlying input stream.
	 */
	public SymmetricKeyEncryptedSessionKeyInputStream(InputStream in)
	{
		super(in, PACKET_TAG_SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY);
	}

	/**
	 * Returns the symmetric algorithm used to encrypt the session key.
	 * 
	 * @return the algorithm
	 * @throws DataFormatException if there is a problem with the PGP data
	 * @throws IOException if an exception is thrown from the underyling stream
	 */
	public int getAlgorithm() throws DataFormatException, IOException
	{
		init();
		return algorithm;
	}

	/**
	 * Returns the S2K algorithm used to generate the symmetric
	 * key that encrypts the session key.
	 * 
	 * @return the S2K algorithm
	 * @throws DataFormatException if there is a problem with the PGP data
	 * @throws IOException if an exception is thrown from the underyling stream
	 */
	public S2kAlgorithm getS2kAlgorithm()
		throws DataFormatException, IOException
	{
		init();
		return s2k;
	}

	/**
	 * Returns the encrypted session key.
	 * 
	 * @return the encrypted session key
	 * @throws DataFormatException if there is a problem with the PGP data
	 * @throws IOException if an exception is thrown from the underyling stream
	 */
	public byte[] getEncryptedSessionKey()
		throws DataFormatException, IOException
	{
		init();
		return encryptedSessionKey;
	}

	protected void engineInit() throws DataFormatException, IOException
	{
		// Read in the version, always 4
		if (super.read() != 4)
			throw new DataFormatException("Invalid version number");

		// Read in the algorithm used (whether this is the algorithm used to
		// encrypt the session key or the actual message remains to be seen
		if ((algorithm = super.read()) == -1)
			throw new DataFormatException("Unexpected EOF while reading algorithm");

		// Read the s2k specifier
		s2k = new S2kAlgorithm(in);

		// Read the encrypted session key, if it is there.
		// If it is there, it will span the remainder of the packet.
		ByteArrayOutputStream b = new ByteArrayOutputStream();
		int x;
		while ((x = super.read()) != -1)
			b.write(x);
		if (b.size() > 0)
			encryptedSessionKey = b.toByteArray();
	}
}