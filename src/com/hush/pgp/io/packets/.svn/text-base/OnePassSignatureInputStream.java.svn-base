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
import com.hush.pgp.Signature;
import com.hush.util.Logger;

/**
 * A stream to read in PGP one pass signature info.
 * <br>
 * The getters should be used to retrieve all information from this stream.
 * The standard <code>read</code> methods will just return EOF.
 * 
 * @author Brian Smith
 *
 */
public class OnePassSignatureInputStream extends PacketContentInputStream
{
	private Signature signature;
	private boolean nested;

	/**
	 * Creates a <code>OnePassSignatureInputStream</code> and saves the argument,
	 * the input stream <code>in</code> for later use.  In most cases
	 * <code>in</code> should be a <code>PacketInputStream</code>.
	 * 
	 * @param in the underlying input stream.
	 */
	public OnePassSignatureInputStream(InputStream in)
	{
		this(in, PACKET_TAG_ONE_PASS_SIGNATURE);
	}

	protected OnePassSignatureInputStream(InputStream in, int packetTag)
	{
		super(in, packetTag);
	}

	/**
	 * Returns the signature retrieved from the stream.
	 * 
	 * @throws DataFormatException if there is a problem with the PGP data
	 * @throws IOException if an exception is thrown from the underyling stream
	 */
	public Signature getSignature() throws DataFormatException, IOException
	{
		init();
		return signature;
	}

	/**
	 * Sets the value of the nested flag, indicating that a message
	 * has multiple one-pass signatures.
	 * 
	 * @throws DataFormatException if there is a problem with the PGP data
	 * @throws IOException if an exception is thrown from the underyling stream
	 */
	protected void engineInit() throws DataFormatException, IOException
	{
		signature = new Signature();
		int b;
		if ((b = read()) != 3)
			throw new DataFormatException(
				"Expected version number of 3; got " + b);
		if ((b = read()) == -1)
			throw new DataFormatException("Unexpected EOF while reading signature type");
		signature.setSignatureType(b);
		if ((b = read()) == -1)
			throw new DataFormatException("Unexpected EOF while reading hash algorithm");
		signature.setHashAlgorithm(b);
		if ((b = read()) == -1)
			throw new DataFormatException("Unexpected EOF while reading public key algorithm");
		signature.setPublicKeyAlgorithm(b);
		byte[] keyID = new byte[8];
		if (read(keyID) != keyID.length)
			throw new DataFormatException("Unexpected EOF while reading issuer key ID");
		Logger.hexlog(this, Logger.DEBUG, "Key ID: ", keyID);
		signature.setIssuerKeyID(keyID, false, false);
		if ((b = read()) == -1)
			throw new DataFormatException("Unexpected EOF while reading nested flag");
		nested = (b == 0);
	}

}
