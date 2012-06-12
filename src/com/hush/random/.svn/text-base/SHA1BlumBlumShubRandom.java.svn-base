/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.random;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

import org.bouncycastle.crypto.digests.SHA1Digest;

import com.hush.util.Conversions;

public class SHA1BlumBlumShubRandom extends SecureRandom
{
	private static final long serialVersionUID = -5345738835821023389L;

	private static final BigInteger ZERO = new BigInteger("0");
	private static final BigInteger ONE = new BigInteger("1");
	private static final BigInteger THREE = new BigInteger("3");
	private static final BigInteger FOUR = new BigInteger("4");

	/**
	 * A default value for the modulus.
	 */
	private static final BigInteger DEFAULT_N =
		new BigInteger("15293446194717093186061791463308919805792451095867568922750749890637229744067250693011089436430694275057036437342179096162775993953435111807812750308137291447496476580542418237958973573718500343979049142183742935886445696622052467427156637448145610378863903515584939551068458225868001373884422921754201642269840101635738031056606168993561826799455186035002503186550040165672097047596338113064507591727169287929123077167692685957181368385712823430329625228619223061362124945361099088025575807316743789685065124176598798008072533797726849916662741499768330081232079014544370233977191448976498762642472846180675850954761");

	// A 128-bit modulus, just in case its needed.
	//public static final BigInteger N = new BigInteger("6412112039624107280416226332922729972120043593112825148417319133258743628977");

	/**
	 * The modulus. The default may be overwridden by the generateN() method.
	 */
	private BigInteger n;

	/**
	 * The current seed value.
	 */
	private BigInteger s;

	/**
	 * A buffer for storing pseudo-random bits.
	 */
	private BigInteger buffer = ZERO;

	/**
	 * The number of bits available in the buffer.
	 */
	private int availableBits = 0;

	private byte[] continuousCheckQueue = new byte[16];
	private int continuousCheckQueuePosition = 0;

	/**
	 * 
	 */
	public SHA1BlumBlumShubRandom()
	{
		this(Conversions.longToBytes(System.currentTimeMillis(), 8));
	}

	/**
	 * @param arg0
	 */
	public SHA1BlumBlumShubRandom(byte[] seed)
	{
		setSeed(seed);
		nextBytes(new byte[8]);
	}

	/**
	 * This method generates a prime that is 3 mod 4.
	 * <p>
	 * @param primeSize The size of the prime to be generated.
	 * @param certainty The degree of certainty required for the primes.
	 * @param source A random source for generating the primes.
	 */
	private BigInteger findPrimeThatIs3Mod4(
		int size,
		int certainty,
		Random source)
	{
		BigInteger result;

		do
		{
			result = new BigInteger(size, certainty, source);
		}
		while (!result.mod(FOUR).equals(THREE));

		return result;
	}

	/**
	 * This method creates a new modulus for use by the PRNG.
	 * If you want to use this method, you will have to
	 * cast a SecureRandom instance to BlumBlumShubRandom.
	 * <p>
	 * @return The new modulus.
	 * @param primeSize The size of each prime in the modulus.
	 * @param certainty The degree of certainty required for the primes.
	 * @param source A random source for generating the primes.
	 */
	public void generateN(int primeSize, int certainty, Random source)
	{
		BigInteger integer1 =
			findPrimeThatIs3Mod4(primeSize, certainty, source);
		BigInteger integer2;

		do
		{
			integer2 = findPrimeThatIs3Mod4(primeSize, certainty, source);
		}
		while (integer1.equals(integer2));

		// Need to block here until other threads release lock on 'this' object.
		synchronized (this)
		{
			n = integer1.multiply(integer2);
		}
	}

	/**
	 * This method generates a 2-logarithm given an argument.
	 *
	 * @return The logarithm.
	 * @param base The base of the logarithm.
	 * @param arg The argument to the algorithm.
	 */
	private int log2(int arg)
	{
		// Base shift formula from elementary school calculus.
		return (int) (Math.log(arg) / Math.log(2));
	}

	/**
	 * This method generates a 2-logarithm given an argument.
	 *
	 * @return The logarithm.
	 * @param base The base of the logarithm.
	 * @param arg The argument to the algorithm.
	 */
	private int log2(BigInteger arg)
	{
		return arg.bitLength();
	}

	/**
	 * Creates a mask with the bitCount leftmost bits set.
	 * <br>
	 * @return The mask.
	 * @param bitCount The number of bits to set.
	 */
	private static BigInteger makeMask(int bitCount)
	{
		double mask = 0;

		for (double x = 0; x < bitCount; x++)
		{
			mask = mask + Math.pow(2, x);
		}

		return new BigInteger(Integer.toString((int) mask));
	}

	/**
	 * This function takes an array of byte arrays, and uses a SHA-1 message
	 * digest to mix them, returning a byte array of the specified length.
	 * <p>
	 * In order to generate byte arrays longer than the hash value (20 bytes), 
	 * one zero byte is mixed into the digest for each extra 20 bytes generated.
	 * <p>
	 * For example, if 60 bytes are required when mixing the values 1, 2, and 3, the
	 * following digests would be taken:
	 * <p>
	 * sha1.update({1,2,3}); sha1.digest();
	 * sha1.update({0,1,2,3}); sha1.digest();
	 * sha1.update({0,0,1,2,3}); sha1.digest();
	 * <p>
	 * Note that increasing the size of the output in this manner does not
	 * alter the amount of entropy in the output.
	 * <p>
	 * This process would be more efficient if the hash didn't reset itself on call
	 * of the digest() method.
	 * <p>
	 * @param values The values to mix.
	 * @param outputSize The required size of the output.
	 */
	private byte[] mixValues(byte[][] values, int outputSize)
	{

		byte[] output = new byte[outputSize];

		byte[] tmpBuffer = new byte[20];

		int bytesCollected = 0;

		for (int zeroPadding = 0; bytesCollected < outputSize; zeroPadding++)
		{
			SHA1Digest digest = new SHA1Digest();

			for (int n = 0; n < zeroPadding; n++)
			{
				digest.update(new byte[] { 0 }, 0, 1);
			}

			for (int n = 0; n < values.length; n++)
			{
				digest.update(values[n], 0, values[n].length);
			}

			int resultLength = digest.doFinal(tmpBuffer, 0);

			int bytesToCopy =
				(resultLength > output.length - bytesCollected)
					? (output.length - bytesCollected)
					: resultLength;

			System.arraycopy(tmpBuffer, 0, output, bytesCollected, bytesToCopy);

			bytesCollected += bytesToCopy;
		}

		return output;
	}

	/**
	 * Fills the byte array with pseudo-random bytes.
	 * <p>
	 * @param results The bytearray to fill with random bytes.
	 */
	public synchronized void nextBytes(byte[] results)
	{

		// Calculate the number of pseudo random bits needed
		int bitsNeeded = results.length * 8;

		// Update the buffer until enough bits are available
		while (availableBits < bitsNeeded)
		{
			updateBuffer();
		}

		// mask off the bytes needed by simply
		// doing an arraycopy
		byte[] bufferBytes = buffer.toByteArray();

		// If the first byte(s) of the buffer is/are zeros, then the bufferBytes array
		// will not be the actual length of the buffer, since those leading zeros
		// are ignored.
		boolean compensateForLeadingZeros = bufferBytes.length < results.length;

		System.arraycopy(
			bufferBytes,
			compensateForLeadingZeros
				? 0
				: (bufferBytes.length - results.length),
			results,
			compensateForLeadingZeros
				? (results.length - bufferBytes.length)
				: 0,
			compensateForLeadingZeros ? bufferBytes.length : results.length);

		if (compensateForLeadingZeros)
		{
			// Wipe the space where the leading zeros would be
			int difference = results.length - bufferBytes.length;
			for (int x = 0; x < difference; x++)
				results[x] = 0;
		}

		// Shift the buffer right to remove the bits that have just been used
		buffer = buffer.shiftRight(bitsNeeded);

		// Decrement the number of bits available in the buffer
		availableBits -= bitsNeeded;

		continuousCheck(results);
	}

	/**
	 * Seeds the generator.
	 * If the generator has already been seeded, the current
	 * value of s is mixed with the new seed.
	 *
	 * @param newseed the seed to be added to the current random seed.
	 */
	public synchronized void setSeed(byte[] seed)
	{
		// Set n to the default if it is null.
		if (n == null)
		{
			n = DEFAULT_N;
		}

		// Clear all stored random bits from the buffer when setting a new seed
		// This is because the first seed may have been weak
		// because the constructor may have seeded the
		// generator with the system time
		buffer = ZERO;
		availableBits = 0;

		// Repeat this step until s is relatively prime to 1.
		// Usually it'll be relatively prime right away, cause N is a product of
		// 2 primes.
		do
		{
			// If the old s is not null, mix it with the seed, otherwise, just mix the seed.
			// Make sure that the new s is the size of n, so that s squared will be greater than n,
			// although this may not be necessary, it doesn't hurt, since the mixing function
			// is very fast.  
			byte[] tempS = mixValues((s == null) ? new byte[][] { seed }
			: new byte[][] { s.toByteArray(), seed }, n.bitLength() / 8);

			s = new BigInteger(tempS);
		}
		while (!s.gcd(n).equals(ONE));

		// After seeding, one cycle should be performed without extracting any random bits
		s = s.multiply(s).mod(n);

		// Note that the buffer is now completely empty.  If we wanted to shift more intensive
		// operations to the seeding process, we could call updateBuffer() a few times here.
		// For now, we'll just wait until nextBytes() is called to start generating pseudo random bits.
	}

	/**
	 * This method updates using the formula s = (s pow 2) mod n,
	 * and updates the buffer that contains random data with the
	 * maximum number of usable random low order bits from the new s.
	 */
	private void updateBuffer()
	{
		// Update s
		s = s.multiply(s).mod(n);

		// Find out how many bits can be used out of the current s.
		// Note!! It is a bug in Schneier 2nd edition.
		int usableBitCount = log2(log2(s));

		if (usableBitCount < 1)
		{
			return;
		}

		// Mask off the current s to get the usable bits
		BigInteger usableBits = s.and(makeMask(usableBitCount));

		// Shift the buffer left to make room for the new bits
		buffer = buffer.shiftLeft(usableBitCount);

		// Add the usable bits to the buffer
		buffer = buffer.or(usableBits);

		availableBits += usableBitCount;
	}

	/**
	 * This is a continous check to ensure that there are not repetitive
	 * values in the random stream.  It conforms to FIPS140-2.
	 */
	private void continuousCheck(byte[] bytes)
	{
		if (bytes.length >= 16)
		{
			System.arraycopy(
				bytes,
				bytes.length - 16,
				continuousCheckQueue,
				0,
				16);
			continuousCheckQueuePosition = 0;
		}
		else
		{
			int remainingQueueSpace = 16 - continuousCheckQueuePosition;
			if (remainingQueueSpace >= bytes.length)
			{
				System.arraycopy(
					bytes,
					0,
					continuousCheckQueue,
					continuousCheckQueuePosition,
					bytes.length);
				continuousCheckQueuePosition =
					(continuousCheckQueuePosition + bytes.length) % 16;
			}
			else
			{
				System.arraycopy(
					bytes,
					0,
					continuousCheckQueue,
					continuousCheckQueuePosition,
					remainingQueueSpace);
				System.arraycopy(
					bytes,
					remainingQueueSpace,
					continuousCheckQueue,
					0,
					bytes.length - remainingQueueSpace);
				continuousCheckQueuePosition =
					bytes.length - remainingQueueSpace;
			}
		}

		// Do the check to be sure the most recent 8 bytes are not
		// equal to the previous 8 bytes
		int pos1 = continuousCheckQueuePosition;
		int pos2;
		for (int x = 0; x < 8; x++)
		{
			pos2 = (pos1 + 8) % 16;
			if (continuousCheckQueue[pos1] != continuousCheckQueue[pos2])
				return;
			pos1 = (pos1 + 1) % 16;
		}
		throw new RuntimeException("Failure of continuous random number generation check");
	}
}