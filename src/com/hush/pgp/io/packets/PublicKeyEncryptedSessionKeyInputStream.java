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
import java.math.BigInteger;

import com.hush.pgp.DataFormatException;
import com.hush.pgp.MPI;

/**
 * A stream to read in a PGP public key encrypted session key.
 * <br>
 * The getters should be used to retrieve all information from this stream.
 * The standard <code>read</code> methods will just return EOF.
 *
 * @author Brian Smith
 *
 */
public class PublicKeyEncryptedSessionKeyInputStream
	extends PacketContentInputStream
{
	private int algorithm;
	private byte[] keyID = new byte[8];
	private BigInteger[] encryptedSessionKey = null;

	/**
	 * Creates a <code>PublicKeyEncryptedSessionKeyInputStream</code> and
	 * saves the argument, the input stream <code>in</code> for later use.
	 * In most cases <code>in</code> should be a
	 * <code>PacketInputStream</code>.
	 * 
	 * @param in the underlying input stream
	 * @throws DataFormatException if there is a problem with the PGP data
	 * @throws IOException if an exception is thrown from the underyling stream
	 */
	public PublicKeyEncryptedSessionKeyInputStream(InputStream in)
	{
		super(in, PACKET_TAG_PUBLIC_KEY_ENCRYPTED_SESSION_KEY);
	}

	/**
	 * Returns the public key algorithm used to encrypt the session key.
	 * 
	 * @return the algorithm.
	 * @throws IOException if the information cannot be retrieved
	 * @throws DataFormatException if there is a problem with the PGP data
	 * @throws IOException if an exception is thrown from the underyling stream
	 */
	public int getAlgorithm() throws DataFormatException, IOException
	{
		init();
		return algorithm;
	}

	/**
	 * Returns the key ID of the key used to encrypt the session key.
	 * 
	 * @return the key ID.
	 * @throws DataFormatException if there is a problem with the PGP data
	 * @throws IOException if an exception is thrown from the underyling stream
	 */
	public byte[] getKeyID() throws DataFormatException, IOException
	{
		init();
		return keyID;
	}

	/**
	 * Returns the encrypted session key.
	 * 
	 * @return the encrypted session key.
	 * @throws DataFormatException if there is a problem with the PGP data
	 * @throws IOException if an exception is thrown from the underyling stream
	 */
	public BigInteger[] getEncryptedSessionKey()
		throws DataFormatException, IOException
	{
		init();
		return encryptedSessionKey;
	}

	protected void engineInit() throws DataFormatException, IOException
	{
		// Read in the version, always 3
		if (read() != 3)
			throw new DataFormatException("Invalid version number");

		// Read in the Key ID, always 8 bytes
		if (read(keyID) != 8)
			throw new DataFormatException("Unexpected EOF while reading key ID");

		// Read in the algorithm ID
		if ((algorithm = read()) == -1)
			throw new DataFormatException("Unexpected EOF while reading algorithm ID");

		// Read the encrypted session key.
		switch (algorithm)
		{
			case CIPHER_ELGAMAL :
			case CIPHER_ELGAMAL_ENCRYPT_ONLY :
				encryptedSessionKey = new BigInteger[2];
				encryptedSessionKey[0] = new MPI(this).getBigInteger();
				encryptedSessionKey[1] = new MPI(this).getBigInteger();
				break;
			case CIPHER_RSA :
			case CIPHER_RSA_ENCRYPT_ONLY :
				encryptedSessionKey = new BigInteger[1];
				encryptedSessionKey[0] = new MPI(this).getBigInteger();
				break;
			default :
				throw new DataFormatException(
					"Unsupported algorithm: " + algorithm);
		}
	}

}
