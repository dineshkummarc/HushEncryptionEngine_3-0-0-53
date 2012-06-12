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

import com.hush.util.Logger;

/**
 * A stream to write out a PGP symmetric key encrypted session key.
 * <br>
 * Based on RFC2440 5.1.
 * <br>
 * The <code>write</code> methods on this stream will fail because all the
 * necessary data is specified in the constructor. This stream should just
 * be constructed and closed. All data will be written to the underlying
 * output stream on close.
 *
 * @author Brian Smith
 *
 */
public class PublicKeyEncryptedSessionKeyOutputStream
	extends PacketContentOutputStream
{
	int algorithm;
	byte[] keyID;
	byte[] encryptedSessionKey;

	/**
	 * Creates a <code>PublicKeyEncryptedSessionKeyOutputStream</code> and
	 * saves the arguments for later use.  In most cases <code>out</code>
	 * should be a <code>PacketInputStream</code>.
	 * 
	 * @param out the underlying output stream.
	 * @param algorithm the public key algorithm used to encrypt the 
	 * session key,
	 * @param keyID the key ID of the key that encrypts the session key.
	 * @param encryptedSessionKey the public key encrypted session key.
	 * @see com.hush.pgp.io.packets.PacketOutputStream
	 * @see com.hush.pgp.PgpConstants
	 */
	public PublicKeyEncryptedSessionKeyOutputStream(
		OutputStream out,
		int algorithm,
		byte[] keyID,
		byte[] encryptedSessionKey)
	{
		super(out, PACKET_TAG_PUBLIC_KEY_ENCRYPTED_SESSION_KEY);

		if (keyID.length != 8)
			throw new IllegalArgumentException("Key ID should be 8 octets");

		// The version, keyID, and the algorithm, and the session key
		int length = 10 + encryptedSessionKey.length;

		setLength(length);

		this.algorithm = algorithm;
		this.keyID = keyID;
		this.encryptedSessionKey = encryptedSessionKey;
	}

	protected void engineInit() throws IOException
	{
		// Write the version tag, which is always 3.
		write(3);

		// Write key ID.
		write(keyID);
		Logger.hexlog(this, Logger.DEBUG, "Wrote key ID: ", keyID);
		keyID = null;

		// Write the type of the encryption algorithm.
		write(algorithm);
		Logger.log(this, Logger.DEBUG, "Wrote algorithm: " + algorithm);

		// Write the encrypted session key.
		write(encryptedSessionKey);
		Logger.hexlog(
			this,
			Logger.DEBUG,
			"Wrote encrypted session key: ",
			encryptedSessionKey);
		encryptedSessionKey = null;
	}
}