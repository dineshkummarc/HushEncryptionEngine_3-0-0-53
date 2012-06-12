/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.pgp.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FilenameFilter;
import java.io.InputStream;
import java.security.SecureRandom;

import com.hush.pgp.Key;
import com.hush.pgp.Keyring;
import com.hush.pgp.Signature;
import com.hush.pgp.io.PgpMessageInputStream;
import com.hush.pgp.io.PgpMessageOutputStream;
import com.hush.util.ArrayTools;
import com.hush.util.Conversions;

/**
 * This class searches all files in the "pgptest" directory for keys, and
 * attempts to encrypt/decrypt/sign/verify using them.F
 */
public class TestPgpKeys
{

	public static final byte[] TEST_STRING =
		{ 0, 0, 0, 0, 0, 0, 0, 0, 64, 64, 64, 64, 64, 64, };
	public static final byte[] PASSPHRASE = "test".getBytes();

	public static void main(String[] argv) throws Exception
	{
		File directory = new File("pgptest");
		File[] files = directory.listFiles(new FilenameFilter()
		{
			public boolean accept(File dir, String name)
			{
				return !(".".equals(name) || "..".equals(name));
			}
		});
		for (int x = 0; x < files.length; x++)
		{
			if (files[x].isFile())
			{
				FileInputStream fileStream = new FileInputStream(files[x]);
				testKeyring(fileStream);
				fileStream.close();
			}
		}
	}

	public static void testKeyring(InputStream in)
	{
		try
		{
			Keyring keyring = new Keyring();
			keyring.load(in);
			keyring.printInformation(System.out);

			Key[] secretKeys = keyring.getKeys(null);
			for (int x = 0; x < secretKeys.length; x++)
			{
				secretKeys[x].decryptSecretKey(PASSPHRASE);
				testKey(secretKeys[x]);
			}
		}
		catch (Throwable t)
		{
			t.printStackTrace(System.out);
		}
	}

	public static void testKey(Key key)
	{
		System.out.println(
			"Key ID: " + Conversions.bytesToHexString(key.getKeyID()));

		//System.out.println(
		//	"Key algorithm: "
		//		+ PgpConstants.PUBLIC_KEY_CIPHER_STRINGS[key.getAlgorithm()]);
		testEncryptDecrypt(key);
	}

	public static void testEncryptDecrypt(Key key)
	{
		try
		{
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			PgpMessageOutputStream pgpOut =
				new PgpMessageOutputStream(out, new SecureRandom());
			pgpOut.addRecipient(key);
			pgpOut.addOnePassSigner(key);
			pgpOut.write(TEST_STRING);
			pgpOut.close();

			//System.out.write(out.toByteArray());

			ByteArrayInputStream in =
				new ByteArrayInputStream(out.toByteArray());
			PgpMessageInputStream pgpIn = new PgpMessageInputStream(in);
			pgpIn.addSecretKey(key);
			out = new ByteArrayOutputStream();
			int x;
			while ((x = pgpIn.read()) != -1)
			{
				out.write(x);
			}

			if (ArrayTools.equals(TEST_STRING, out.toByteArray()))
			{
				System.out.println("Encrypt/decrypt successful");
			}
			else
			{
				System.out.println("Encrypt/decrypt failed");
			}

			pgpIn.close();

			Signature[] sigs = pgpIn.getSignatures();

			if (sigs.length != 1)
			{
				System.out.println("Found no signature in output");
				System.out.println("Signature/verification failed");
			}

			sigs[0].finishVerification(key);

			System.out.println("Signature/verification successful");
		}
		catch (Throwable t)
		{
			t.printStackTrace(System.out);
		}
	}
}
