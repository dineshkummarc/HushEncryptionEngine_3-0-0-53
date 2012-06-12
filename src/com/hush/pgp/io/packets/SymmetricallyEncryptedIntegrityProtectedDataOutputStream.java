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
import java.security.SecureRandom;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import com.hush.pgp.AlgorithmFactory;

/**
 * A stream to write out PGP symmetrically encrypted integrity
 * protected data.
 *
 * @author Brian Smith
 *
 */
public class SymmetricallyEncryptedIntegrityProtectedDataOutputStream
	extends SymmetricallyEncryptedDataOutputStream
{

	protected Digest digest;
	protected boolean digestCompleted = false;

	/**
	 * Creates a <code>SymmetricallyEncryptedDataOutputStream</code>
	 * and saves the arguments for later use.  In most cases
	 * <code>out</code> should be a <code>PacketOutputStream</code>.
	 *
	 * @param out the underlying output stream.
	 * @param algorithm the symmetric key algorithm to be used.
	 * @param key the key that will encrypt the data.
	 * @param plaintextLength the length of the data to be written; -1 if unknown.
	 * @see com.hush.pgp.PgpConstants
	 * @see com.hush.pgp.io.packets.PacketOutputStream
	 */
	public SymmetricallyEncryptedIntegrityProtectedDataOutputStream(
		OutputStream out,
		int algorithm,
		byte[] key,
		int plaintextLength)
	{
		super(
			out,
			algorithm,
			key,
			plaintextLength,
			PACKET_TAG_SYMMETRICALLY_ENCRYPTED_INTEGRITY_PROTECTED_DATA);
		digest = AlgorithmFactory.getDigest(HASH_SHA1);
	}

	/**
	 * Creates a <code>SymmetricallyEncryptedDataOutputStream</code>
	 * and saves the arguments for later use.  In most cases
	 * <code>out</code> should be a <code>PacketOutputStream</code>.
	 *
	 * @param out the underlying output stream.
	 * @param algorithm the symmetric key algorithm to be used.
	 * @param key the key that will encrypt the data.
	 * @see com.hush.pgp.PgpConstants
	 * @see com.hush.pgp.io.packets.PacketOutputStream
	 */
	public SymmetricallyEncryptedIntegrityProtectedDataOutputStream(
		OutputStream out,
		int algorithm,
		byte[] key)
	{
		this(out, algorithm, key, -1);
	}

	/**
	 * Closes this stream and the underlying stream.
	 * 
	 * @see java.io.OutputStream#close()
	 */
	public void close() throws IOException
	{
		write(0xd3);
		write(0x14);
		write(getDigestResult(new byte[0]));
		super.close();
	}

	/**
	 * After the all data has been written to the stream,
	 * this method can be used to retrieve the digest of the data.
	 * 
	 * @return the digest result.
	 */
	public byte[] getDigestResult(byte[] b)
	{
		if (digestCompleted)
			throw new IllegalStateException("Already got digest result");

		// Digest any extra bytes suggested
		if (b != null)
			digest.update(b, 0, b.length);
		byte[] digestResult = new byte[HASH_LENGTHS[HASH_SHA1]];
		digest.doFinal(digestResult, 0);
		digestCompleted = true;
		return digestResult;
	}

	protected byte[] engineInit2(KeyParameter keyParam)
	{
		byte[] iv = new byte[cipher.getBlockSize()];
		ParametersWithIV cfbParams = new ParametersWithIV(keyParam, iv);
		byte[] initBytes = new byte[cipher.getBlockSize() + 2];
		new SecureRandom().nextBytes(initBytes);
		System.arraycopy(
			initBytes,
			cipher.getBlockSize() - 2,
			initBytes,
			cipher.getBlockSize(),
			2);
		cipher.init(true, cfbParams);
		byte[] encryptedInitBytes = new byte[1 + cipher.getBlockSize()];
		encryptedInitBytes[0] = (byte) 0x01;
		digest.update(initBytes, 0, initBytes.length);
		cipher.processBytes(
				initBytes,
				0,
				initBytes.length,
				encryptedInitBytes,
				1);
		return encryptedInitBytes;
	}

	protected void handleWrittenBytes(byte[] b, int off, int len)
	{
		if (!digestCompleted)
			digest.update(b, off, len);
	}

	protected long calculateLength(long length)
	{
		// We know that the cipher text length will be the plaintext length
		// plus the initial bytes for the cipher, including the version and
		// the 2 repeated bytes.
		// If integrity rotected, add 1 for the version number.
		return ((length < 0) ? -1 : (length + cipher.getBlockSize() + 3));
	}
}
