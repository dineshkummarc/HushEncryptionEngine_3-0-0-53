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
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.DESedeParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import com.hush.pgp.AlgorithmFactory;
import com.hush.pgp.DataFormatException;
import com.hush.pgp.cfb.CFBParameters;
import com.hush.pgp.cfb.WrongKeyException;
import com.hush.util.Conversions;
import com.hush.util.Logger;

/**
 * A stream to read in PGP symmetrically encrypted data.
 *
 * @author Brian Smith
 * 
 */
public class SymmetricallyEncryptedDataInputStream
	extends PacketContentInputStream
{
	private BufferedBlockCipher cipher;
	private int[] algorithm;

	protected byte[] buffer;
	protected int bufferSize = 0;
	protected int bufferStart = 0;
	
	private byte[] encryptedBuffer;
	private int encryptedBufferSize = 0;
	private int encryptedBufferStart = 0;
	
	protected int packetTag = PACKET_TAG_SYMMETRICALLY_ENCRYPTED_DATA;
	private byte[][] sessionKeys;

	/**
	 * Creates a <code>SymmetricallyEncryptedDataInputStream</code> and saves 
	 * the arguments, the input stream <code>in</code>, the symmetric key
	 * algorithm <code>algorithm</code> and the key <code>key</code> for
	 * later use.  In most cases <code>in</code> should be a 
	 * <code>PacketInputStream</code>.
	 * 
	 * @param in the underlying input stream
	 * @param algorithm the algorithm that encrypts the data
	 * @param sessionKeys an array of keys with which to attempt to decrypt the data
	 * @see com.hush.pgp.PgpConstants
	 */
	public SymmetricallyEncryptedDataInputStream(
		InputStream in,
		int[] algorithm,
		byte[][] sessionKeys)
	{
		this(
			in,
			algorithm,
			sessionKeys,
			PACKET_TAG_SYMMETRICALLY_ENCRYPTED_DATA);
	}

	protected SymmetricallyEncryptedDataInputStream(
		InputStream in,
		int[] algorithm,
		byte[][] sessionKeys,
		int packetTag)
	{
		super(in, packetTag);
		Logger.log(this, Logger.DEBUG, "Algorithm: " + algorithm);
		this.algorithm = algorithm;
		this.sessionKeys = sessionKeys;
	}

	/**
	 * @see java.io.InputStream#read()
	 * @throws DataFormatException if there is a problem with the PGP data
	 * @throws IOException if an exception is thrown from the underyling stream
	 * @throws WrongKeyException if none of the session keys will decrypt the data
	 */
	public int read()
		throws DataFormatException, IOException, WrongKeyException
	{
		byte[] toRead = new byte[1];
		int readCount = read(toRead, 0, 1);
		if (readCount != 1)
			return -1;
		return (Conversions.unsignedByteToInt(toRead[0]));
	}

	/**
	 * @see java.io.InputStream#read(byte[])
	 * @throws DataFormatException if there is a problem with the PGP data
	 * @throws IOException if an exception is thrown from the underyling stream
	 * @throws WrongKeyException if none of the session keys will decrypt the data
	 */
	public int read(byte[] b)
		throws DataFormatException, IOException, WrongKeyException
	{
		return read(b, 0, b.length);
	}

	/**
	 * @see java.io.InputStream#read(byte[], int, int)
	 * @throws DataFormatException if there is a problem with the PGP data
	 * @throws IOException if an exception is thrown from the underyling stream
	 * @throws WrongKeyException if none of the session keys will decrypt the data
	 */
	public synchronized int read(byte[] b, int off, int len)
		throws DataFormatException, IOException, WrongKeyException
	{
		init();

		// This variable tracks how many bytes we are returning.
		// May be less than or equal to len.
		int bytesRead;

		// Copy the appropriate number of bytes from the buffer to the output
		int amountToCopyOutOfBuffer = len < bufferSize ? len : bufferSize;
		System.arraycopy(buffer, bufferStart, b, off, amountToCopyOutOfBuffer);

		// Reset the buffer based on the number of bytes just read
		bufferSize -= amountToCopyOutOfBuffer;
		bufferStart =
			(bufferSize == 0) ? 0 : bufferStart + amountToCopyOutOfBuffer;

		// Calculate the amount needed outside of the buffer
		int amountNeeded = len - amountToCopyOutOfBuffer;

		if (amountNeeded == 0)
		{
			// There were enough bytes in the buffer to cover everything.
			// We can skip the upcoming read and decryption attempts.
			bytesRead = amountToCopyOutOfBuffer;
		}
		else
		{
			// If we've gotten here, it means we need read more data from the
			// wrapped stream and decrypt it.

			// Caculate and read the number of bytes we need to decrypt to get
			// the number of bytes we want to return.
			/*  Not CLDC compliant
			int needToDecrypt =
				cipher.getBlockSize()
					* (int) Math.ceil(
						(double) amountNeeded / (double) cipher.getBlockSize());
			*/

			int needToDecrypt =
				cipher.getBlockSize()
					* ((amountNeeded + (cipher.getBlockSize() - 1))
						/ cipher.getBlockSize());

			byte[] toDecrypt = new byte[needToDecrypt];
			
			int amountToCopyFromEncryptedBuffer =
				encryptedBufferSize > needToDecrypt ?
							needToDecrypt : encryptedBufferSize;
			if ( amountToCopyFromEncryptedBuffer > 0 )
			{
				System.arraycopy(encryptedBuffer, encryptedBufferStart,
						toDecrypt, 0,
						amountToCopyFromEncryptedBuffer);
				encryptedBufferSize -= amountToCopyFromEncryptedBuffer;
				encryptedBufferStart += amountToCopyFromEncryptedBuffer;
			}
			
			int stillNeeded = needToDecrypt - amountToCopyFromEncryptedBuffer;
			int cipherTextRead = 0;
			
			if ( stillNeeded > 0 )
			{
				cipherTextRead = super.read(toDecrypt,
					amountToCopyFromEncryptedBuffer,
					stillNeeded);
			}
			
			if (cipherTextRead == -1)
			{
				// We've reached EOF on the wrapped stream.
				// If we got anything out of the buffer return that.  Otherwise
				// return -1, indicating end of file.
				bytesRead =
					amountToCopyOutOfBuffer == 0 ? -1 : amountToCopyOutOfBuffer;
			}
			else
			{
				cipherTextRead += amountToCopyFromEncryptedBuffer;
				
				byte[] decrypted =
					new byte[cipher.getUpdateOutputSize(cipherTextRead)];

				boolean needToDoFinal = false;

				if (decrypted.length < amountNeeded)
				{
					needToDoFinal = true;
					decrypted = new byte[cipherTextRead];
				}

				
				
				int amountDecrypted =
					cipher.processBytes(
						toDecrypt,
						0,
						cipherTextRead,
						decrypted,
						0);

				try
				{
					if (needToDoFinal)
						amountDecrypted
							+= cipher.doFinal(decrypted, amountDecrypted);
				}
				catch (InvalidCipherTextException e)
				{
					throw DataFormatException.wrap(
							"Invalid cipher text during decryption", e);
				}

				// Copy the decrypted data into the output
				int amountToCopyIntoOutput =
					amountNeeded < amountDecrypted
						? amountNeeded
						: amountDecrypted;
				System.arraycopy(
					decrypted,
					0,
					b,
					amountToCopyOutOfBuffer + off,
					amountToCopyIntoOutput);

				// Put any leftover bytes in the buffer.
				// Note that the buffer will always be empty at this point, because we wouldn't
				// have had to decrypt any new data if we hadn't used up the entire buffer first.
				bufferSize = amountDecrypted - amountToCopyIntoOutput;
				System.arraycopy(
					decrypted,
					amountToCopyIntoOutput,
					buffer,
					bufferStart,
					bufferSize);

				bytesRead = amountToCopyOutOfBuffer + amountToCopyIntoOutput;
			}
		}

		// Perform any special operations with the bytes about to be returned.
		handleReadBytes(b, off, bytesRead);

		return bytesRead;
	}

	protected BufferedBlockCipher createCipher(int algorithm)
	{
		return AlgorithmFactory.getPGPCFBBlockCipher(algorithm);
	}

	protected CipherParameters createCipherParameters(byte[] key, int algorithm)
	{
		KeyParameter keyParam;
		if (algorithm == CIPHER_3DES)
			keyParam = new DESedeParameters(key);
		else
			keyParam = new KeyParameter(key);
		return new CFBParameters(keyParam);
	}

	protected void handleReadBytes(byte[] b, int offset, int len)
		throws DataFormatException, IOException
	{
	}

	protected int getInitBytesLength()
	{
		return getMaxBlockSize() + 2;
	}

	protected int getMaxBlockSize()
	{
		int biggestCipher = 0;
		for (int x = 0; x < algorithm.length; x++)
		{
			if (SYMMETRIC_CIPHER_BLOCK_LENGTHS[algorithm[x]] > biggestCipher)
			{
				biggestCipher = SYMMETRIC_CIPHER_BLOCK_LENGTHS[algorithm[x]];
			}
		}
		return biggestCipher;
	}
	
	protected void initializeCipher(
		BufferedBlockCipher cipher,
		byte[] initBytes,
		CipherParameters parameters)
		throws WrongKeyException
	{
		byte[] realInitBytes = trimAndBufferInitBytes(initBytes,
				cipher.getBlockSize() + 2);
		System.arraycopy(initBytes, 0, realInitBytes, 0, realInitBytes.length);
		((CFBParameters) parameters).setInitBytes(realInitBytes);
		cipher.init(false, parameters);
	}

	protected byte[] trimAndBufferInitBytes(byte[] initBytes, int bytesUsed)
	{
		byte[] realInitBytes = new byte[bytesUsed];
		System.arraycopy(initBytes, 0, realInitBytes, 0, realInitBytes.length);
		encryptedBuffer = new byte[initBytes.length - realInitBytes.length];
		encryptedBufferSize = encryptedBuffer.length;
		encryptedBufferStart = 0;
		System.arraycopy(initBytes, realInitBytes.length, encryptedBuffer, 0,
				encryptedBuffer.length);
		return realInitBytes;
	}
	
	protected void tryAllKeys(byte[] initBytes) throws WrongKeyException
	{
		boolean failed = true;
		BufferedBlockCipher thisCipher = null;
		for (int x = 0; x < sessionKeys.length && failed; x++)
		{
			Logger.hexlog(
				this,
				Logger.DEBUG,
				"Trying session key: ",
				sessionKeys[x]);
			Logger.hexlog(this, Logger.DEBUG, "Init bytes: ", initBytes);
			failed = false;
			try
			{
				CipherParameters parameters =
					createCipherParameters(sessionKeys[x], algorithm[x]);
				buffer = new byte[SYMMETRIC_CIPHER_BLOCK_LENGTHS[algorithm[x]]];
				thisCipher = createCipher(algorithm[x]);
				initializeCipher(thisCipher, initBytes, parameters);
			}
			catch (Throwable t)
			{
				Logger.logThrowable(this, Logger.WARNING, "Symmetric key failure: ", t);
				failed = true;
				//cipher = createCipher(algorithm[x]);
			}
		}
		if ( thisCipher == null )
			throw new IllegalStateException("No ciphers to try");
		if (failed == true)
			throw new WrongKeyException("No available key will decrypt the data");
		cipher = thisCipher;
	}

	protected void engineInit()
		throws WrongKeyException, DataFormatException, IOException
	{
		byte[] initBytes = new byte[getInitBytesLength()];
		int initByteCount = super.read(initBytes);
		if (initByteCount != initBytes.length)
			throw new DataFormatException("Unexpected EOF while reading initial cipher bytes");
		tryAllKeys(initBytes);
	}
}
