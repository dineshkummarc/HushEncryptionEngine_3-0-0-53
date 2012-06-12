/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.pgp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;

import org.bouncycastle.crypto.Digest;

import com.hush.util.Logger;

/**
 * A S2kAlgorithm is an algorithm that converts a string (passphrase) to a symmetric encryption
 * key. This class implements all the algorithms specified in rfc 2440, i.e 
 *                simple S2K, 
 *                salted S2K and 
 *                iterated-and-salted S2K. 
 *
 * Simple should not be used since it is very vulnerable to a dictionary attacks.
 *
 * @author Magnus Hessel
 */
public class S2kAlgorithm implements PgpConstants, Serializable
{
	private static final long serialVersionUID = -7575439662802985235L;
	private int myType;
	private int myHash;
	private byte[] mySalt = new byte[8];
	private int myCount;
	private int myDigestLen;

	public S2kAlgorithm(int type, int hash, byte[] salt, int count)
	{
		myType = type;
		myCount = getEncodableIterationCount(count);
		//if (salt.length != 8)
		//	throw new IllegalArgumentException("Salt must be 8 bytes");
		mySalt = salt;
		myHash = hash;
		myDigestLen = HASH_LENGTHS[myHash];
	}

	public S2kAlgorithm(InputStream in) throws IOException
	{
		myType = in.read();

		if (myType != S2K_TYPE_SIMPLE
			&& myType != S2K_TYPE_SALTED
			&& myType != S2K_TYPE_ITERATED_AND_SALTED)
			throw new IOException("Invalided S2K type");

		if ((myHash = in.read()) == -1)
			throw new IOException("Unexpected EOF while reading hash type");

		if (myType >= S2K_TYPE_SALTED)
		{
			if (in.read(mySalt) != 8)
				throw new IOException("Unexpected EOF while reading salt");
		}

		if (myType == S2K_TYPE_ITERATED_AND_SALTED)
		{
			if ((myCount = in.read()) == -1)
				throw new IOException("Unexpected EOF while reading hash iteration count");
			myCount = decodeCount(myCount);
		}

		myDigestLen = HASH_LENGTHS[myHash];
	}

	public byte[] getBytes()
	{
		try
		{
			ByteArrayOutputStream output = new ByteArrayOutputStream();
			output.write(myType);
			output.write(myHash);
			if (myType == S2K_TYPE_SALTED)
				output.write(mySalt);
			else if (myType == S2K_TYPE_ITERATED_AND_SALTED)
			{
				output.write(mySalt);
				output.write(encodeIterationCount(myCount));
			}
			return output.toByteArray();
		}
		catch (IOException e)
		{
			throw new RuntimeException();
		}
	}

	protected byte[] engineDoHash(
		byte[] passphrase,
		int numberOfOctetsToBeHashed,
		byte[] salt,
		int assumedSessionKeyLength)
	{
		byte[] saltNpassphrase = new byte[salt.length + passphrase.length];
		System.arraycopy(salt, 0, saltNpassphrase, 0, salt.length);
		System.arraycopy(
			passphrase,
			0,
			saltNpassphrase,
			salt.length,
			passphrase.length);

		int numberOfHashes =
			(assumedSessionKeyLength + myDigestLen - 1) / myDigestLen;

		// Set the hash machines up in parallell
		Digest[] digestContexts = new Digest[numberOfHashes];

		for (int i = 0; i < numberOfHashes; i++)
		{
			digestContexts[i] = AlgorithmFactory.getDigest(myHash);

			// preload
			for (int j = 0; j < i; j++)
				digestContexts[i].update((byte) 0x00);
		}

		for (int i = 0; i < numberOfHashes; i++)
		{
			digestContexts[i].update(
				saltNpassphrase,
				0,
				saltNpassphrase.length);
		}

		int updated = saltNpassphrase.length;

		// update till you have updated preloaded 'numberOfOctetsToBeHashed'
		while (updated < numberOfOctetsToBeHashed)
		{
			if ((updated + saltNpassphrase.length) <= numberOfOctetsToBeHashed)
			{
				// update with the full digest
				for (int i = 0; i < numberOfHashes; i++)
					digestContexts[i].update(
						saltNpassphrase,
						0,
						saltNpassphrase.length);

				updated += saltNpassphrase.length;
			}
			else
			{
				//update only with the remaining part
				byte[] arr = new byte[numberOfOctetsToBeHashed - updated];
				System.arraycopy(saltNpassphrase, 0, arr, 0, arr.length);

				for (int i = 0; i < numberOfHashes; i++)
					digestContexts[i].update(arr, 0, arr.length);

				updated += arr.length;
			}
		}

		byte[] out = new byte[assumedSessionKeyLength];

		for (int i = 0; i < digestContexts.length; i++)
		{
			byte[] digestResult = new byte[digestContexts[i].getDigestSize()];
			digestContexts[i].doFinal(digestResult, 0);
			System.arraycopy(
				digestResult,
				0,
				out,
				i * myDigestLen,
				Math.min(
					assumedSessionKeyLength - (i * myDigestLen),
					myDigestLen));
		}

		return out;
	}

	public byte[] s2k(byte[] passphrase, int assumedSessionKeyLength)
	{
		Logger.hexlog(this, Logger.DEBUG, "Performing S2K on: ", passphrase);
		Logger.log(this, Logger.DEBUG, "S2K type: " + myType);
		Logger.log(this, Logger.DEBUG, "S2K hash: " + myHash);
		Logger.hexlog(this, Logger.DEBUG, "S2K salt: ", mySalt);
		Logger.log(
			this,
			Logger.DEBUG,
			"S2K encoded count: " + encodeIterationCount(myCount));
		Logger.log(this, Logger.DEBUG, "S2K decoded count: " + myCount);
		byte[] result;
		switch (myType)
		{
			case S2K_TYPE_SIMPLE :
				result = s2kSimple(passphrase, assumedSessionKeyLength);
				break;
			case S2K_TYPE_SALTED :
				result = s2kSalted(passphrase, assumedSessionKeyLength);
				break;
			case S2K_TYPE_ITERATED_AND_SALTED :
				result =
					s2kIteratedAndSalted(passphrase, assumedSessionKeyLength);
				break;
			default :
				throw new IllegalArgumentException(
					"Unrecognized S2K-Specifier first octet " + myType);
		}
		Logger.hexlog(this, Logger.DEBUG, "S2K result: ", result);
		return result;
	}

	/**
	 * Returns the closest larger iteration count that is valid for
	 * encoding.
	 */
	public static int getEncodableIterationCount(int count)
	{
		int[] result = calculateIterationCount(count);
		return result[0];
	}

	public static int encodeIterationCount(int count)
	{
		int[] result = calculateIterationCount(count);
		return result[1];
	}

	private static int[] calculateIterationCount(int count)
	{
		for (int c = 0; c < 0xFF; c++)
		{
			int thisCount = ((16 + (c & 15)) << ((c >> 4) + 6));
			if (thisCount >= count)
			{
				return new int[] { thisCount, c };
			}
		}
		throw new IllegalArgumentException("S2K iteration count too large");
	}

	private static int decodeCount(int c)
	{
		return ((16 + (c & 15)) << ((c >> 4) + 6));
	}

	protected byte[] s2kIteratedAndSalted(
		byte[] passphrase,
		int assumedOutputLength)
	{
		return engineDoHash(passphrase, myCount, mySalt, assumedOutputLength);
	}

	protected byte[] s2kSalted(byte[] passphrase, int assumedOutputLength)
	{
		return engineDoHash(passphrase, 0, mySalt, assumedOutputLength);
	}

	protected byte[] s2kSimple(byte[] passphrase, int assumedSessionKeyLength)
	{
		return engineDoHash(passphrase, 0, new byte[] {
		}, assumedSessionKeyLength);
	}
}