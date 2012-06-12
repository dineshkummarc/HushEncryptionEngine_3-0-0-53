package com.hush.test.pgp;

import com.hush.pgp.*;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.*;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;

public class BadSignatures
{
	public static Signature stringToSignature(String sigin)
	{
		try
		{
			Signature[] sigs = Signature.load(new ByteArrayInputStream(sigin
					.getBytes(PgpConstants.UTF8)));
			if (sigs.length != 1)
				throw new IllegalArgumentException(
						"Expected one signature, got: " + sigs.length);
			return sigs[0];
		}
		catch (IOException e)
		{
			throw new RuntimeException(e);
		}
	}

	public static String replaceHash(String sigin, InputStream data)
			throws IOException
	{
		return replaceHash(stringToSignature(sigin), data).toString();
	}

	public static String swapMPIs(String sigin)
			throws IOException
	{
		return swapMPIs(stringToSignature(sigin)).toString();
	}
	
	public static Signature replaceHash(Signature sigin, InputStream data)
			throws IOException
	{
		Digest newDigest;
		switch (sigin.getHashAlgorithm())
		{
		case PgpConstants.HASH_SHA256:
			newDigest = new SHA256Digest();
			break;
		case PgpConstants.HASH_MD5:
			newDigest = new MD5Digest();
			break;
		case PgpConstants.HASH_RIPEMD160:
			newDigest = new RIPEMD160Digest();
			break;
		case PgpConstants.HASH_SHA1:
			newDigest = new SHA1Digest();
			break;
		default:
			throw new IllegalArgumentException("Unknown hash: "
					+ sigin.getHashAlgorithm());
		}
		byte[] buffer = new byte[4096];
		for (int x = 0; x != -1; x = data.read(buffer))
		{
			newDigest.update(buffer, 0, x);
		}
		byte[] result = new byte[newDigest.getDigestSize()];
		newDigest.doFinal(result, 0);
		sigin.setLeftSixteenBitsOfHash(new byte[]
		{ result[0], result[1] });
		return sigin;
	}

	public static Signature swapMPIs(Signature sigin) throws IOException
	{
		MPI[] mpis = sigin.getSignatureMPIs();
		MPI[] newMPIs = new MPI[mpis.length];
		for (int x = 0; x < mpis.length; x++)
		{
			newMPIs[x] = new MPI(mpis[x].getBigInteger().add(new BigInteger("1")));
		}
		sigin.setSignatureMPIs(newMPIs);
		return sigin;
	}
}