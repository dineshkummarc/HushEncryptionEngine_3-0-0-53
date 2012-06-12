package com.hush.test.pgp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Iterator;

import com.hush.pgp.Key;
import com.hush.pgp.PgpConstants;
import com.hush.pgp.io.PgpMessageInputStream;
import com.hush.pgp.io.PgpMessageOutputStream;

import junit.framework.TestCase;

public class TestKey extends TestCase
{

	private static HashSet testKeys;

	private static SecureRandom random = new SecureRandom();

	public static int[] VERSIONS = new int[]
	{ 4 };


	public static int[] KEY_ALGORITHMS = new int[]
	{ PgpConstants.CIPHER_RSA, PgpConstants.CIPHER_RSA_ENCRYPT_ONLY,
			PgpConstants.CIPHER_RSA_SIGN_ONLY, PgpConstants.CIPHER_DSA,
			PgpConstants.CIPHER_ELGAMAL,
			PgpConstants.CIPHER_ELGAMAL_ENCRYPT_ONLY };
	
	public static Key.KeyType[] KEY_TYPES = new Key.KeyType[]
 	{ Key.KeyType.BOTH, Key.KeyType.ENCRYPTION, Key.KeyType.SIGNING, 
		Key.KeyType.BOTH, Key.KeyType.BOTH, Key.KeyType.ENCRYPTION };

	/*
	 public int[] KEY_ALGORITHMS = new int[]
	 { PgpConstants.CIPHER_DSA };
	 */
	public static int[] KEY_SIZES = new int[]
	{ 512, 1024, 2048 };

	static
	{
		testKeys = new HashSet();
		for (int x = 0; x < KEY_ALGORITHMS.length; x++)
		{
			System.err
					.println("Algorithm: "
							+ PgpConstants.PUBLIC_KEY_CIPHER_STRINGS[KEY_ALGORITHMS[x]]);
			for (int y = 0; y < KEY_SIZES.length; y++)
			{
				if ( KEY_ALGORITHMS[x] == PgpConstants.CIPHER_DSA &&
						KEY_SIZES[y] == 2048 ) continue;
				if ( KEY_ALGORITHMS[x] == PgpConstants.CIPHER_ELGAMAL &&
						KEY_SIZES[y] != 2048 ) continue;
				if ( KEY_ALGORITHMS[x] == PgpConstants.CIPHER_ELGAMAL_ENCRYPT_ONLY &&
						KEY_SIZES[y] != 2048 ) continue; 
				for (int z = 0; z < VERSIONS.length; z++)
				{

					Key key = new Key(VERSIONS[z],
							System.currentTimeMillis() / 1000,
							KEY_ALGORITHMS[x], KEY_SIZES[y], KEY_TYPES[x], random);
					testKeys.add(key);
				}
			}
		}
	}

	public void testEncryptDecrypt() throws Exception
	{
		String testString = "test test test test";
		for (Iterator i = testKeys.iterator(); i.hasNext();)
		{
			Key key = (Key) i.next();
			ByteArrayOutputStream encrypted = new ByteArrayOutputStream();
			PgpMessageOutputStream pgpOut = new PgpMessageOutputStream(
					encrypted, random);
			try
			{
				pgpOut.addRecipient(key);
			}
			catch (IllegalArgumentException e)
			{
				if (!(key.getAlgorithm() == PgpConstants.CIPHER_RSA_SIGN_ONLY || key
						.getAlgorithm() == PgpConstants.CIPHER_DSA))
				{
					fail("Should be able to encrypt with this key");
				}
				//pgpOut.close();
				continue;
			}
			if (key.getAlgorithm() == PgpConstants.CIPHER_RSA_SIGN_ONLY
					|| key.getAlgorithm() == PgpConstants.CIPHER_DSA)
			{
				fail("Shouldn't be able to encrypt with this key");
			}
			pgpOut.write(testString.getBytes());
			pgpOut.close();

			ByteArrayInputStream toDecrypt = new ByteArrayInputStream(
					encrypted.toByteArray());
			ByteArrayOutputStream decrypted = new ByteArrayOutputStream();
			PgpMessageInputStream pgpIn = new PgpMessageInputStream(
					toDecrypt);
			pgpIn.addSecretKey(key);

			byte[] buffer = new byte[2048];
			int x;
			while ((x = pgpIn.read(buffer)) != -1)
			{
				decrypted.write(buffer, 0, x);
			}
			assertEquals(new String(decrypted.toByteArray()), testString);
		}
	}
}