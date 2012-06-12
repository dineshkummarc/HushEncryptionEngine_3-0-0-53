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

import com.hush.pgp.Key;
import com.hush.pgp.MPI;
import com.hush.util.Conversions;
import com.hush.util.Logger;

/**
 * A stream to write out a PGP public key.
 * <br>
 * Based on RFC2440 5.5.2.
 * <br>
 * The <code>write</code> methods on this stream will fail because all the
 * necessary data is specified in the constructor. This stream should just
 * be constructed and closed. All data will be written to the underlying
 * output stream on close.
 * 
 * @author Brian Smith
 *
 */
public class PublicKeyOutputStream extends PacketContentOutputStream
{
	private Key key;

	/**
	 * Creates a <code>PublicKeyOutputStream</code> and
	 * saves the arguments for later use.  In most cases <code>out</code>
	 * should be a <code>PacketInputStream</code>.
	 * 
	 * @param out the underlying output stream.
	 * @param key the key to write to the underlying stream.
	 * @see com.hush.pgp.io.packets.PacketOutputStream
	 * @see com.hush.pgp.Key
	 */
	public PublicKeyOutputStream(OutputStream out, Key key) throws IOException
	{
		this(out, key, PACKET_TAG_PUBLIC_KEY);
	}

	/**
	 * Creates a <code>PublicKeyOutputStream</code> and
	 * saves the arguments for later use.  In most cases <code>out</code>
	 * should be a <code>PacketInputStream</code>.
	 * 
	 * @param out the underlying output stream.
	 * @param key the key to write to the underlying stream.
	 * @param tag the packet tag for the underlying stream.
	 * @see com.hush.pgp.io.packets.PacketOutputStream
	 */
	protected PublicKeyOutputStream(OutputStream out, Key key, int tag)
	{
		super(out, tag);
		this.key = key;
	}

	protected byte[] getSecretKeyMaterial(Key key)
	{
		return new byte[0];
	}

	protected void engineInit() throws IOException
	{
		byte[] mpis = MPI.mpis2Bytes(key.getPublicKeyMPIs());
		byte[] secretKeyMaterial = getSecretKeyMaterial(key);
		if (key.getVersion() < 4)
			setLength(8 + mpis.length + secretKeyMaterial.length);
		else
			setLength(6 + mpis.length + secretKeyMaterial.length);
		Logger.log(this, Logger.DEBUG, "Version: " + key.getVersion());
		write(key.getVersion());
		byte[] creationTimeBytes = new byte[4];
		Conversions.longToBytes(key.getCreationTime(), creationTimeBytes, 0, 4);
		write(creationTimeBytes);
		Logger.hexlog(this, Logger.DEBUG, "Creation time bytes: ", creationTimeBytes);
		if (key.getVersion() < 4)
		{
			byte[] validityBytes = new byte[2];
			Conversions.longToBytes(
				key.getKeyExpirationTime(),
				validityBytes,
				0,
				2);
			write(validityBytes);
			Logger.hexlog(this, Logger.DEBUG, "Validity bytes: ", creationTimeBytes);
		}
		write(key.getAlgorithm());
		Logger.log(this, Logger.DEBUG, "Algorithm: " + key.getAlgorithm());
		key = null;
		write(mpis);
		Logger.hexlog(this, Logger.DEBUG, "MPIS: ", mpis);
		write(secretKeyMaterial);
	}
}