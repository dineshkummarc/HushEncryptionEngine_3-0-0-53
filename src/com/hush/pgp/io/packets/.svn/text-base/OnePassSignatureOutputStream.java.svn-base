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

import com.hush.pgp.Signature;

/**
 * A stream to write out a PGP one-pass signature.
 * <br>
 * Based on RFC2440 5.4.
 * <br>
 * The <code>write</code> methods on this stream will fail because all the
 * necessary data is specified in the constructor. This stream should just
 * be constructed and closed. All data will be written to the underlying
 * output stream on close.
 * 
 * @author Brian Smith
 *
 */
public class OnePassSignatureOutputStream extends PacketContentOutputStream
{
	private Signature signature;
	private boolean nested;

	/**
	 * Creates a <code>OnePassSignatureOutputStream</code> and saves the 
	 * arguments for later use. In most cases, <code>out</code> should be a 
	 * PacketOutputStream.
	 * 
	 * @param out the underlying output stream.
	 * @param signature the signature to write to the underlying stream.
	 * @param nested true if there are multiple signatures on the message.
	 * @see com.hush.pgp.io.packets.PacketOutputStream
	 * @see com.hush.pgp.Signature
	 */
	public OnePassSignatureOutputStream(
		OutputStream out,
		Signature signature,
		boolean nested)
	{
		super(out, PACKET_TAG_ONE_PASS_SIGNATURE);
		this.signature = signature;
		this.nested = nested;
		setLength(13);
	}

	protected void engineInit() throws IOException
	{
		// The version is currently 3.
		write(3);
		
		write(signature.getSignatureType());
		write(signature.getHashAlgorithm());
		write(signature.getPublicKeyAlgorithm());
		write(signature.getIssuerKeyID(false));
		write(nested ? 0 : 1);
	}
}