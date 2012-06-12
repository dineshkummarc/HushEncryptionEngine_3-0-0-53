/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.pgp.cfb;

import java.security.SecureRandom;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;

import com.hush.util.Logger;

/**
 * Implements a Cipher-FeedBack (CFB) mode on top of a simple cipher.
 * 
 * This is OpenPGP CFB, as described in RFC2440 12.8
 * 
 * @author Brian Smith (based on Bouncy Castle code)
 */
public class CFBBlockCipher implements BlockCipher
{
	private byte[] cfbV;
	private byte[] cfbOutV;

	private int blockSize;
	private BlockCipher cipher = null;
	private boolean encrypting;

	private CFBParameters params;

	/**
	 * Basic constructor.
	 *
	 * @param cipher the block cipher to be used as the basis of the
	 * feedback mode.
	 * @param bitBlockSize the block size in bits (note: a multiple of 8)
	 */
	public CFBBlockCipher(BlockCipher cipher, int bitBlockSize)
	{
		this.cipher = cipher;
		this.blockSize = bitBlockSize / 8;

		this.cfbV = new byte[cipher.getBlockSize()];
		this.cfbOutV = new byte[cipher.getBlockSize()];
	}

	/**
	 * return the underlying block cipher that we are wrapping.
	 *
	 * @return the underlying block cipher that we are wrapping.
	 */
	public BlockCipher getUnderlyingCipher()
	{
		return cipher;
	}

	/**
	 * Initialise the cipher and, possibly, the initialisation vector (IV).
	 * If an IV isn't passed as part of the parameter, the IV will be all zeros.
	 * An IV which is too short is handled in FIPS compliant fashion.
	 *
	 * @param encrypting if true the cipher is initialised for
	 *  encryption, if false for decryption.
	 * @param cipherParams the key and other data required by the cipher.
	 * @exception IllegalArgumentException if the params argument is
	 * inappropriate.
	 */
	public void init(boolean encrypting, CipherParameters cipherParams)
		throws IllegalArgumentException
	{
		this.cfbV = new byte[cipher.getBlockSize()];
		this.cfbOutV = new byte[cipher.getBlockSize()];

		this.encrypting = encrypting;

		if (cipherParams instanceof CFBParameters)
		{
			params = (CFBParameters) cipherParams;
		}
		else
		{
			throw new IllegalArgumentException("Must initialize with CFBParameters");
		}

		// Init for encryption - CFB mode is weird, the cipher is always
		// encrypting.
		cipher.init(true, params.getParameters());

		byte[] initBytes = new byte[blockSize + 2];

		// Encrypt FR (currently the 0 IV) to create FRE.
		cipher.processBlock(cfbV, 0, cfbOutV, 0);

		Logger.hexlog(this, Logger.DEBUG, "Encrypted zero IV: ", cfbOutV);

		// Generate the random prefix,
		byte[] prefix;
		prefix = new byte[blockSize];

		// If encrypting generate the random prefix
		// otherwise, figure it out.
		if (encrypting)
		{
			new SecureRandom().nextBytes(prefix);
		}
		else
		{
			prefix = new byte[params.getInitBytes().length];
			System.arraycopy(
				params.getInitBytes(),
				0,
				prefix,
				0,
				prefix.length);
			for (int x = 0; x < blockSize; x++)
				prefix[x] ^= cfbOutV[x];
		}

		Logger.hexlog(this, Logger.DEBUG, "Random prefix: ", prefix);

		// XOR the random prefix with FRE
		for (int x = 0; x < blockSize; x++)
			cfbOutV[x] ^= prefix[x];

		// FRE is now C1 - C8, so copy it to the output buffer
		System.arraycopy(cfbOutV, 0, initBytes, 0, blockSize);

		// Load C1 - C8 into FR
		System.arraycopy(cfbOutV, 0, cfbV, 0, blockSize);

		// Encrypt FR to create FRE
		cipher.processBlock(cfbV, 0, cfbOutV, 0);

		// Left two octets of FRE get XOR-ed with the last two octets of 
		// the prefix.
		for (int x = 0; x < 2; x++)
			cfbOutV[x] ^= prefix[blockSize - 2 + x];

		// If we're decrypting, make sure those two octets match up with
		// the last two bytes in the prefix
		if (!encrypting)
		{
			for (int x = 0; x < 2; x++)
			{
				if (prefix[blockSize + x] != cfbOutV[x])
				{
					throw new WrongKeyException("An attempt was made to decrypt data with the wrong key");
				}
			}
		}

		// This makes C9 - C10, so copy into the output buffer
		System.arraycopy(cfbOutV, 0, initBytes, blockSize, 2);

		// RESYNC STEP - Load up the FR with C3 - C10
		System.arraycopy(initBytes, 2, cfbV, 0, blockSize);

		// Encrypt FR to create FRE
		cipher.processBlock(cfbV, 0, cfbOutV, 0);

		// Save the prefix in the parameters.
		params.setInitBytes(initBytes);

	}

	/**
	 * return the algorithm name and mode.
	 *
	 * @return the name of the underlying algorithm followed by "/CFB"
	 * and the block size in bits.
	 */
	public String getAlgorithmName()
	{
		return cipher.getAlgorithmName() + "/CFB" + (blockSize * 8);
	}

	/**
	 * return the block size we are operating at.
	 *
	 * @return the block size we are operating at (in bytes).
	 */
	public int getBlockSize()
	{
		return blockSize;
	}

	/**
	 * Process one block of input from the array in and write it to
	 * the out array.
	 *
	 * @param in the array containing the input data.
	 * @param inOff offset into the in array the data starts at.
	 * @param out the array the output data will be copied into.
	 * @param outOff the offset into the out array the output will start at.
	 * @exception DataLengthException if there isn't enough data in in, or
	 * space in out.
	 * @exception IllegalStateException if the cipher isn't initialised.
	 * @return the number of bytes processed and produced.
	 */
	public int processBlock(byte[] in, int inOff, byte[] out, int outOff)
		throws DataLengthException, IllegalStateException
	{
		return (encrypting)
			? encryptBlock(in, inOff, out, outOff)
			: decryptBlock(in, inOff, out, outOff);
	}

	/**
	 * Do the appropriate processing for PGPCFB mode encryption.
	 *
	 * @param in the array containing the data to be encrypted.
	 * @param inOff offset into the in array the data starts at.
	 * @param out the array the encrypted data will be copied into.
	 * @param outOff the offset into the out array the output will start at.
	 * @exception DataLengthException if there isn't enough data in in, or
	 * space in out.
	 * @exception IllegalStateException if the cipher isn't initialised.
	 * @return the number of bytes processed and produced.
	 */
	public int encryptBlock(byte[] in, int inOff, byte[] out, int outOff)
		throws DataLengthException, IllegalStateException
	{
		if ((inOff + blockSize) > in.length)
		{
			throw new DataLengthException("input buffer too short");
		}

		if ((outOff + blockSize) > out.length)
		{
			throw new DataLengthException("output buffer too short");
		}

		cipher.processBlock(cfbV, 0, cfbOutV, 0);

		//
		// XOR the cfbV with the plaintext producing the cipher text
		//
		for (int i = 0; i < blockSize; i++)
		{
			out[outOff + i] = (byte) (cfbOutV[i] ^ in[inOff + i]);
		}

		//
		// change over the input block.
		//

		// WTF - This was in the original CFB code, but does nothing.
		//System.arraycopy(cfbV, blockSize, cfbV, 0, cfbV.length - blockSize);

		System.arraycopy(out, outOff, cfbV, cfbV.length - blockSize, blockSize);

		return blockSize;
	}

	/**
	 * Do the appropriate processing for CFB mode decryption.
	 *
	 * @param in the array containing the data to be decrypted.
	 * @param inOff offset into the in array the data starts at.
	 * @param out the array the encrypted data will be copied into.
	 * @param outOff the offset into the out array the output will start at.
	 * @exception DataLengthException if there isn't enough data in in, or
	 * space in out.
	 * @exception IllegalStateException if the cipher isn't initialised.
	 * @return the number of bytes processed and produced.
	 */
	public int decryptBlock(byte[] in, int inOff, byte[] out, int outOff)
		throws DataLengthException, IllegalStateException
	{
		if ((inOff + blockSize) > in.length)
		{
			throw new DataLengthException("input buffer too short");
		}

		if ((outOff + blockSize) > out.length)
		{
			throw new DataLengthException("output buffer too short");
		}

		cipher.processBlock(cfbV, 0, cfbOutV, 0);

		//
		// change over the input block.
		//

		// WTF - This was in the original CFB code, but does nothing.
		//System.arraycopy(cfbV, blockSize, cfbV, 0, cfbV.length - blockSize);

		System.arraycopy(in, inOff, cfbV, cfbV.length - blockSize, blockSize);

		//
		// XOR the cfbV with the plaintext producing the plain text
		//
		for (int i = 0; i < blockSize; i++)
		{
			out[outOff + i] = (byte) (cfbOutV[i] ^ in[inOff + i]);
		}

		return blockSize;
	}

	/**
	 * reset the chaining vector back to the IV and reset the underlying
	 * cipher.
	 */
	public void reset()
	{
		cipher.reset();
	}
}
