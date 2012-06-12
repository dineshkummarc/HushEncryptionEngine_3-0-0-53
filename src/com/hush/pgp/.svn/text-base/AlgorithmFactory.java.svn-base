/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.pgp;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.Digest;

import com.hush.pgp.cfb.CFBBlockCipher;
import com.hush.util.ExceptionWrapper;

/**
 * This class contains static methods that accept constant integers and
 * return algorithm implementations.
 */
public class AlgorithmFactory implements PgpConstants
{
	public static BlockCipher getBlockCipher(int algorithm)
	{
		try
		{
			BlockCipher engine;
			switch (algorithm)
			{
				case CIPHER_3DES :
					engine =
						(BlockCipher) Class
							.forName("org.bouncycastle.crypto.engines.DESedeEngine")
							.newInstance();
					break;
				case CIPHER_TWOFISH :
					engine =
						(BlockCipher) Class
							.forName("org.bouncycastle.crypto.engines.TwofishEngine")
							.newInstance();
					break;
				case CIPHER_AES128 :
				case CIPHER_AES192 :
				case CIPHER_AES256 :
					engine =
						(BlockCipher) Class
							.forName("org.bouncycastle.crypto.engines.AESEngine")
							.newInstance();
					break;
				case CIPHER_BLOWFISH :
					try
					{
						// Try to use the Hush legacy blowfish if it's available.
						// It will be included in packages that support old Hushmail
						// messages that included backwards compatibility with
						// messages created using a key expansion bug.
						engine =
							(BlockCipher) Class
								.forName("com.hush.hee.legacy.LegacyBlowfishEngine")
								.newInstance();
					}
					catch (ClassNotFoundException e)
					{
						engine =
							(BlockCipher) Class
								.forName("org.bouncycastle.crypto.engines.BlowfishEngine")
								.newInstance();
					}
					break;
				case CIPHER_CAST5 :
					engine =
						(BlockCipher) Class
							.forName("org.bouncycastle.crypto.engines.CAST5Engine")
							.newInstance();
					break;
				case CIPHER_IDEA :
					engine =
						(BlockCipher) Class
							.forName("org.bouncycastle.crypto.engines.IDEAEngine")
							.newInstance();
					break;
				default :
					throw new IllegalArgumentException(
						"Unknown algorithm: " + algorithm);
			}
			return engine;
		}
		catch (ClassNotFoundException e)
		{
			throw ExceptionWrapper.wrapInRuntimeException("Unable to load algorithm: "
					+ algorithm, e);
		}
		catch (InstantiationException e)
		{
			throw ExceptionWrapper.wrapInRuntimeException("Unable to load algorithm: "
					+ algorithm, e);
		}
		catch (IllegalAccessException e)
		{
			throw ExceptionWrapper.wrapInRuntimeException("Unable to load algorithm: "
					+ algorithm, e);
		}
	}

	public static BufferedBlockCipher getPGPCFBBlockCipher(int algorithm)
	{
		BlockCipher engine = getBlockCipher(algorithm);
		BufferedBlockCipher cipher =
			new BufferedBlockCipher(
				new CFBBlockCipher(engine, engine.getBlockSize() * 8));
		return cipher;
	}

	/**
	 * This method is to retrieve a cipher that uses standard CFB mode, not
	 * the modified mode PGP uses otherwise.
	 */
	public static BufferedBlockCipher getStandardCFBBlockCipher(int algorithm)
	{
		BlockCipher engine = getBlockCipher(algorithm);
		BufferedBlockCipher cipher =
			new BufferedBlockCipher(
				new org.bouncycastle.crypto.modes.CFBBlockCipher(
					engine,
					engine.getBlockSize() * 8));
		return cipher;
	}

	public static Digest getDigest(int algorithm)
	{
		try
		{
			Digest digest;
			switch (algorithm)
			{
				case HASH_MD5 :
					digest =
						(Digest) Class
							.forName("org.bouncycastle.crypto.digests.MD5Digest")
							.newInstance();
					break;
				case HASH_SHA1 :
					digest =
						(Digest) Class
							.forName("org.bouncycastle.crypto.digests.SHA1Digest")
							.newInstance();
					break;
				case HASH_RIPEMD160 :
					digest =
						(Digest) Class
							.forName("org.bouncycastle.crypto.digests.RIPEMD160Digest")
							.newInstance();
					break;
				case HASH_SHA256 :
					digest =
						(Digest) Class
							.forName("org.bouncycastle.crypto.digests.SHA256Digest")
							.newInstance();
					break;
				case HASH_SHA384 :
					digest =
						(Digest) Class
							.forName("org.bouncycastle.crypto.digests.SHA384Digest")
							.newInstance();
					break;
				case HASH_SHA512 :
					digest =
						(Digest) Class
							.forName("org.bouncycastle.crypto.digests.SHA512Digest")
							.newInstance();
					break;
				default :
					throw new IllegalArgumentException(
						"Unknown algorithm: " + algorithm);
			}
			return digest;
		}
		catch (ClassNotFoundException e)
		{
			throw ExceptionWrapper.wrapInRuntimeException("Unable to load algorithm: "
					+ algorithm, e);
		}
		catch (InstantiationException e)
		{
			throw ExceptionWrapper.wrapInRuntimeException("Unable to load algorithm: "
					+ algorithm, e);
		}
		catch (IllegalAccessException e)
		{
			throw ExceptionWrapper.wrapInRuntimeException("Unable to load algorithm: "
					+ algorithm, e);
		}
	}
	
	public static int getHashID(String hashName)
	{
		for (int x = 0; x < HASH_STRINGS.length; x++)
		{
			if (hashName.equalsIgnoreCase(HASH_STRINGS[x]))
			{
				return x;
			}
		}
		throw new IllegalArgumentException("Unsupported hash algorithm: "
			+ hashName);
	}
	
	public static int getPublicKeyCipherID(String cipherName)
	{
		for (int x = 0; x < PUBLIC_KEY_CIPHER_STRINGS.length; x++)
		{
			if (cipherName.equalsIgnoreCase(PUBLIC_KEY_CIPHER_STRINGS[x]))
			{
				return x;
			}
		}
		throw new IllegalArgumentException("Unsupported cipher algorithm: "
			+ cipherName);
	}
	
	public static int getSymmetricCipherID(String cipherName)
	{
		for (int x = 0; x < SYMMETRIC_CIPHER_STRINGS.length; x++)
		{
			if (cipherName.equalsIgnoreCase(SYMMETRIC_CIPHER_STRINGS[x]))
			{
				return x;
			}
		}
		throw new IllegalArgumentException("Unsupported cipher algorithm: "
			+ cipherName);
	}
}