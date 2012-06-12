/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.pgp;

import java.io.Serializable;

import com.hush.util.Conversions;

/**
 * Identifies the signature targeted by another signature as described in 
 * RFC 2440 5.2.3.25.
 *
 * @author Brian Smith
 */
public class SignatureTarget implements Serializable
{
	private static final long serialVersionUID = 5255114484619213450L;
	int publicKeyAlgorithm;
	int hashAlgorithm;
	byte[] hash;

	public SignatureTarget(byte[] data)
	{
		publicKeyAlgorithm = Conversions.unsignedByteToInt(data[0]);
		hashAlgorithm = Conversions.unsignedByteToInt(data[1]);
		hash = new byte[data.length - 2];
		System.arraycopy(data, 2, hash, 0, hash.length);
	}

	public SignatureTarget(
		int publicKeyAlgorithm,
		int hashAlgorithm,
		byte[] hash)
	{
		this.publicKeyAlgorithm = publicKeyAlgorithm;
		this.hashAlgorithm = hashAlgorithm;
		this.hash = hash;
	}

	public byte[] getBytes()
	{
		byte[] data = new byte[hash.length + 2];
		data[0] = (byte) publicKeyAlgorithm;
		data[1] = (byte) hashAlgorithm;
		System.arraycopy(hash, 0, data, 2, hash.length);
		return data;
	}

	public int getPublicKeyAlgorithm()
	{
		return publicKeyAlgorithm;
	}

	public int getHashAlgorithm()
	{
		return hashAlgorithm;
	}

	public byte[] getHash()
	{
		return hash;
	}
}
