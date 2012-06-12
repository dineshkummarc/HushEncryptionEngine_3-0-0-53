/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.hee;

import com.hush.pgp.MPI;
import com.hush.util.Conversions;

import java.security.SecureRandom;

/**
 * Implementation of a secret sharing scheme with three participants where
 * the access structure is any pair of participants. 
 *
 * The construction is the one from Corollary 1.2 [Cor12] of "Decomposition Construction
 * for Secret Sharing Shemes" by D. R. Stinson. It is similar to the polymomial
 * construction by Shamir except for that we do not require the order of the   
 * Galois field over which aritmetics are performed to be prime but merely power of a prime. 
 * We choose base 2 for simplicity.
 *
 * Let us call the participants P1, P2 and P3. The graph for the access structure is off course a triangle
 *
 *                        P1
 *                /                \
 *         P2            --          P3
 *
 * which is a complete multipartite graph K1,1,1 having the obvios three disjoins vertex sets 
 * {P1},{P2} and {P3}.
 *
 * The values from the proof of Cor12 chosen
 * are x1 = 1
 *     x2 = 2
 *            x3 = 3
 *
 * K is off course the secret and r an arbitrary integer < q, randomly chosen
 * and not revealed.
 *
 * Note that since our access structure is a complete multipartite graph, [Cor12]
 * guarantees that we have a perfect scharing scheme. It also shows that the information
 * rate is optimal. Hence there is no need to even try to find a graph decomposition for
 * the given graph.
 *
 * Creation date: (27/07/2001 16:20:46)
 * @author Magnus Hessel
 */
import java.math.BigInteger;

public class LineInterpolation
{
	// Length in bytes. Needed not to reveal short secrets (passphrases).
	int MIN_LENGTH = 128;

	// Secure random to use.
	SecureRandom myRandom;

	// Prime power.
	BigInteger myQ;
	
	// shadows
	BigInteger[] myShadows = new BigInteger[3];
	BigInteger ONE = new BigInteger("1");
	BigInteger TWO = new BigInteger("2");
	BigInteger THREE = new BigInteger("3");
	int myLength = -1;

	public LineInterpolation()
	{
		super();
	}

	/**
	 * Generate shadows of a secret.
	 *
	 * Creation date: (27/07/2001 16:21:36)
	 */
	public void generate(byte[] secret)
	{
		validateSecret(secret);
		
		BigInteger k = new BigInteger(1, secret);
		generateQ(k.bitLength()+1);

		BigInteger r = generateR();

		// P1 =  + r
		myShadows[0] = k.add(r).mod(myQ);

		// P2 = x
		myShadows[1] = k.multiply(TWO).add(r).mod(myQ);

		myShadows[2] = k.multiply(THREE).add(r).mod(myQ);
	}

	private void generateQ(int messageMagnitude)
	{
		int length = Math.max(messageMagnitude, MIN_LENGTH);
		myLength = length;
		myQ = TWO.pow(length);
	}

	private BigInteger generateR()
	{
		BigInteger r = null;

		// r have to be smaller than q
		do
		{
			r = new BigInteger(myQ.bitLength(), myRandom);
		}
		while (myQ.compareTo(r) <= 0);

		return r;
	}

	/**
	 * Get an encoded shadow given an index. An encoded shadow consists of three MPIs
	 *
	 *        - index (0->2)
	 *        - length of Q
	 *        - shadow value
	 *
	 * Creation date: (27/07/2001 16:25:26)
	 * @return java.math.BigInteger
	 * @param index int
	 */
	public byte[] getEncodedShadow(int index)
	{
		// Encode as a sequence of MPIs
		// * index
		// * length (of Q)
		// * Shadow
		return MPI.mpis2Bytes(
			new MPI[] {
				new MPI(BigInteger.valueOf(index)),
				new MPI(BigInteger.valueOf(myLength)),
				new MPI(getShadow(index))});
	}

	/**
	 * Get the shadow Pi
	 * Use index
	 *                P1:        0
	 *                P2: 1
	 *                 P3: 2
	 * Creation date: (27/07/2001 16:25:26)
	 * @return java.math.BigInteger
	 * @param index int
	 */
	private BigInteger getShadow(int index)
	{
		return myShadows[index];
	}

	public byte[] reconstruct()
	{
		if (myQ == null)
		{
			throw new IllegalStateException("Must set prime power p");
		}

		if (myShadows[0] == null)
		{
			return reconstruct12();
		}

		if (myShadows[1] == null)
		{
			return reconstruct02();
		}

		return reconstruct01();
	}

	protected byte[] reconstruct01()
	{
		if ((myShadows[0] == null) || (myShadows[1] == null))
		{
			throw new IllegalStateException();
		}

		// Solve m the equations in GF(p)
		//  r +  K = s[0]
		//  r + 2K = s[1]
		//
		// M = s[1] - s[0]
		BigInteger m = myShadows[1].subtract(myShadows[0]).mod(myQ);

		return getBytes(m);
	}

	protected byte[] reconstruct02()
	{
		if ((myShadows[0] == null) || (myShadows[2] == null))
		{
			throw new IllegalStateException();
		}

		// Solve m the equations in GF(p)
		//  r + K = s[0]
		//  r + 3K = s[2]
		//
		// M = s[2] - s[0])/2
		BigInteger m = myShadows[2].subtract(myShadows[0]).mod(myQ).divide(TWO);
		return getBytes(m);
	}

	protected byte[] reconstruct12()
	{
		if ((myShadows[1] == null) || (myShadows[2] == null))
		{
			throw new IllegalStateException();
		}

		// Solve m the equations in GF(p)
		// r  + 2K = s[1]
		// r  + 3K = s[2]
		//
		// M = (s[2] - s[1])
		BigInteger m = myShadows[2].subtract(myShadows[1]).mod(myQ);
		return getBytes(m);
	}

	/**
	 * Set an encoded shadow. An encoded shadow consists of three MPIs
	 *
	 *        - index (0->2)
	 *        - length of Q
	 *        - shadow value
	 *
	 * Creation date: (27/07/2001 16:25:26)
	 * @return java.math.BigInteger
	 * @param index int
	 */
	public void setEncodedShadow(byte[] encodedShadow)
	{
		MPI[] mpis = MPI.parseAllMPIs(encodedShadow, 0, encodedShadow.length);
		int index = mpis[0].getBigInteger().intValue();
		int length = mpis[1].getBigInteger().intValue();

		if ((myLength != -1) && (myLength != length))
		{
			throw new IllegalArgumentException("Public length does not match other shadow");
		}

		myLength = length;
		myQ = TWO.pow(myLength);
		setShadow(mpis[2].getBigInteger(), index);
	}

	/**
	 * Set random to choose.
	 *
	 * Creation date: (27/07/2001 17:07:07)
	 * @param random hushclone.java.security.SecureRandom
	 */
	public void setRandom(SecureRandom random)
	{
		myRandom = random;
	}

	/**
	 * Set the shadow Pi
	 * Use index
	 *                P1:        0
	 *                P2: 1
	 *                 P3: 2
	 * Creation date: (27/07/2001 16:25:26)
	 * @return java.math.BigInteger
	 * @param index int
	 */
	private void setShadow(BigInteger shadow, int index)
	{
		myShadows[index] = shadow;
	}

	public static byte[] getBytes(BigInteger integer)
	{
		// BigInteger.getBytes() is buggy and may return a bytearray beginning with a zero byte.
		return Conversions.bigIntegerToUnsignedBytes(integer);
	}
	
	public static void validateSecret(byte[] secret)
	{
		if (secret == null)
			throw new IllegalArgumentException("Secret cannot be null");

		if (secret.length == 0)
			throw new IllegalArgumentException("Secret cannot be zero length");
	}
}