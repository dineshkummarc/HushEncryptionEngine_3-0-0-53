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

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.DESedeParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import com.hush.pgp.AlgorithmFactory;
import com.hush.pgp.cfb.WrongKeyException;
import com.hush.pgp.io.IntegrityCheckFailureException;
import com.hush.util.ArrayTools;
import com.hush.util.Logger;

/**
 * A stream to read in PGP symmetrically encrypted data.
 * <br>
 * When this stream reaches EOF, it checks the MDC, so be sure to read
 * all the way up to the EOF, even if you don't need all the data.
 *
 * @author Brian Smith
 *
 */
public class SymmetricallyEncryptedIntegrityProtectedDataInputStream
	extends SymmetricallyEncryptedDataInputStream
{
	private Digest digest;
	private byte[] digestBuffer = new byte[HASH_LENGTHS[HASH_SHA1]];
	private int digestBufferStart = 0;
	private int digestBufferSize = 0;
	private boolean mdcChecked = false;

	/**
	 * Creates a 
	 * <code>SymmetricallyEncryptedIntegrityProtectedDataInputStream</code>
	 * and saves the arguments, the input stream <code>in</code>, the 
	 * symmetric key algorithm <code>algorithm</code> and the key
	 * <code>key</code> for later use.  In most cases <code>in</code> should
	 * be a <code>PacketInputStream</code>.
	 * 
	 * @param in the underlying input stream.
	 * @param algorithm the algorithm that encrypts the data.
	 * @param key the key that encrypts the data.
	 * @see com.hush.pgp.PgpConstants
	 */
	public SymmetricallyEncryptedIntegrityProtectedDataInputStream(
		InputStream in,
		int[] algorithm,
		byte[][] sessionKeys)
	{
		super(
			in,
			algorithm,
			sessionKeys,
			PACKET_TAG_SYMMETRICALLY_ENCRYPTED_INTEGRITY_PROTECTED_DATA);
		digest = AlgorithmFactory.getDigest(HASH_SHA1);
	}

	protected BufferedBlockCipher createCipher(int algorithm)
	{
		return AlgorithmFactory.getStandardCFBBlockCipher(algorithm);
	}

	protected CipherParameters createCipherParameters(byte[] key, int algorithm)
	{
		KeyParameter keyParam;
		if (algorithm == CIPHER_3DES)
			keyParam = new DESedeParameters(key);
		else
			keyParam = new KeyParameter(key);
		return new ParametersWithIV(keyParam, 
			new byte[SYMMETRIC_CIPHER_BLOCK_LENGTHS[algorithm]]);
	}

	protected int getInitBytesLength()
	{
		return 1 + (getMaxBlockSize() * 2);
	}

	protected void initializeCipher(
		BufferedBlockCipher cipher,
		byte[] initBytes,
		CipherParameters parameters)
		throws WrongKeyException
	{
		initBytes = trimAndBufferInitBytes(initBytes,
				1 + (cipher.getBlockSize() * 2));
		cipher.init(false, parameters);
		int amountDecrypted =
			cipher.processBytes(
				initBytes,
				1,
				initBytes.length - 1,
				initBytes,
				1);
		if (amountDecrypted != initBytes.length - 1)
			throw new RuntimeException("Unexpected failure to decrypt all the inital cipher bytes");
		Logger.hexlog(
			this,
			Logger.DEBUG,
			"Verifying initial cipher bytes: ",
			initBytes);
		if (initBytes[cipher.getBlockSize() - 1]
			!= initBytes[cipher.getBlockSize() + 1]
			|| initBytes[cipher.getBlockSize()]
				!= initBytes[cipher.getBlockSize() + 2])
			throw new WrongKeyException("An attempt was made to decrypt data with the wrong key");
		digest.update(initBytes, 1, cipher.getBlockSize() + 2);
		bufferSize = cipher.getBlockSize() - 2;
		System.arraycopy(
			initBytes,
			cipher.getBlockSize() + 3,
			buffer,
			0,
			bufferSize);
	}

	protected void handleReadBytes(byte[] b, int offset, int len)
		throws IOException
	{
		if (len != -1)
		{
			if (mdcChecked)
				throw new IllegalStateException("Bytes read after MDC check");

			digestUpdate(b, offset, len);
		}
		else
		{
			if (mdcChecked)
				return;

			byte[] digestResult = new byte[HASH_LENGTHS[HASH_SHA1]];
			digest.doFinal(digestResult, 0);
			byte[] digestFromMDCPacket = new byte[HASH_LENGTHS[HASH_SHA1]];

			System.arraycopy(
				digestBuffer,
				digestBufferStart,
				digestFromMDCPacket,
				0,
				digestBuffer.length - digestBufferStart);
			System.arraycopy(
				digestBuffer,
				0,
				digestFromMDCPacket,
				digestBuffer.length - digestBufferStart,
				digestBufferStart);

			Logger.hexlog(
				this,
				Logger.DEBUG,
				"Stored MDC: ",
				digestFromMDCPacket);

			Logger.hexlog(this, Logger.DEBUG, "Calculated MDC: ", digestResult);

			if (!ArrayTools.equals(digestResult, digestFromMDCPacket))
				throw new IntegrityCheckFailureException("Failed modification detection check");

			mdcChecked = true;
		}
	}

	private void digestUpdate(byte[] b, int offset, int len)
	{
		int totalAvailableBytes = digestBufferSize + len;

		int bytesToDigest = totalAvailableBytes - digestBuffer.length;

		int bytesToPutInBuffer = 0;
		int bytesToPutInBufferOffset = offset;

		if (bytesToDigest > 0)
		{
			// Update digest with first buffer bytes
			int bufferBytesToDigest =
				bytesToDigest < digestBufferSize
					? bytesToDigest
					: digestBufferSize;

			int firstBufferBytesToDigest =
				digestBuffer.length - digestBufferStart < bufferBytesToDigest
					? digestBuffer.length - digestBufferStart
					: bufferBytesToDigest;

			digest.update(
				digestBuffer,
				digestBufferStart,
				firstBufferBytesToDigest);

			digestBufferStart =
				(digestBufferStart + firstBufferBytesToDigest)
					% digestBuffer.length;

			int secondBufferBytesToDigest =
				bufferBytesToDigest - firstBufferBytesToDigest;

			digest.update(
				digestBuffer,
				digestBufferStart,
				secondBufferBytesToDigest);

			digestBufferStart += secondBufferBytesToDigest;

			digestBufferSize -= bufferBytesToDigest;

			// Now digest any of the bytes in b that we need to
			int nonBufferBytesToDigest = bytesToDigest - bufferBytesToDigest;

			digest.update(b, offset, nonBufferBytesToDigest);

			// Now copy any remaining bytes to the buffer
			bytesToPutInBuffer = len - nonBufferBytesToDigest;
			bytesToPutInBufferOffset = offset + nonBufferBytesToDigest;
		}
		else
		{
			bytesToPutInBuffer = len;
		}

		int placeToStartCopying =
			(digestBufferStart + digestBufferSize) % digestBuffer.length;

		int firstBufferSegment =
			digestBuffer.length - placeToStartCopying < bytesToPutInBuffer
				? digestBuffer.length - placeToStartCopying
				: bytesToPutInBuffer;

		System.arraycopy(
			b,
			bytesToPutInBufferOffset,
			digestBuffer,
			placeToStartCopying,
			firstBufferSegment);

		placeToStartCopying =
			(placeToStartCopying + firstBufferSegment) % digestBuffer.length;

		System.arraycopy(
			b,
			bytesToPutInBufferOffset + firstBufferSegment,
			digestBuffer,
			placeToStartCopying,
			bytesToPutInBuffer - firstBufferSegment);

		digestBufferSize += bytesToPutInBuffer;
	}

	protected void finalize()
	{
		if (!mdcChecked)
			Logger.log(
				this,
				Logger.ERROR,
				"Failed to check MDC; message may have been altered");
	}
}
