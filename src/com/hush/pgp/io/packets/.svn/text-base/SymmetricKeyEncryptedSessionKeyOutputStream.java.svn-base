/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

/*
 * A stream to write out a PGP symmetric key encrypted session key.
 *
 * Based on RFC2440 5.3.
 *
 * All you can do with this class is call a constructor.  The data is
 * immediately written and the stream is closed.  Any further attempts.
 * to write to the stream will fail.
 *
 * @author Brian Smith
 *
 */
package com.hush.pgp.io.packets;

import java.io.IOException;
import java.io.OutputStream;

import com.hush.pgp.S2kAlgorithm;

public class SymmetricKeyEncryptedSessionKeyOutputStream extends
	PacketContentOutputStream
{

	public SymmetricKeyEncryptedSessionKeyOutputStream(OutputStream out,
		int cipherAlgorithm, S2kAlgorithm s2k)
		throws IOException
	{
		this(out, cipherAlgorithm,
			s2k, null); 
	}

	public SymmetricKeyEncryptedSessionKeyOutputStream(OutputStream out,
		int cipherAlgorithm,
		S2kAlgorithm s2k,
		byte[] encryptedSessionKey)
		throws IOException
	{
		super(out, PACKET_TAG_SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY);

		int length = 2; // The version and the algorithm

		byte[] s2kBytes = s2k.getBytes();
		
		length += s2kBytes.length;
		

		// If a key is being included
		if ( encryptedSessionKey != null )
		{
			// The encrypted key
			length += encryptedSessionKey.length;
		}

		setLength(length);

		// Write the version tag, which is always 4
		write(4);
		
		// Write the type of the encryption algorithm
		write(cipherAlgorithm);

		// Write the s2k butes
		write(s2kBytes);
		
		// Write the hash algorithm

		if ( encryptedSessionKey != null )
		{
			write(encryptedSessionKey);
		}
	}
	
	public void engineInit() throws IOException {}
}