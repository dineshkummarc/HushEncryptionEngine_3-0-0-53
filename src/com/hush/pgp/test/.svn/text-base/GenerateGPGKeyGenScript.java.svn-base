/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.pgp.test;

/**
 * This class generates a script that can be fed to "gpg --batch --gen-key".
 * This will result in the population of keyrings with a wide range of values.
 */
public class GenerateGPGKeyGenScript
{
	public static int n = 0;

	public static final int MAIN_RSA = 0;
	public static final int MAIN_RSA_S = 1;
	public static final int MAIN_DSA = 2;
	public static final int MAIN_ELG = 3;

	public static final int SUB_RSA = 0;
	public static final int SUB_RSA_E = 1;
	public static final int SUB_ELG_E = 2;
	public static final int SUB_ELG = 3;

	public static final int L768 = 0;
	public static final int L1024 = 1;
	public static final int L2048 = 2;

	public static void main(String argv[])
	{
		for (int mainKeyType = 0; mainKeyType < 4; mainKeyType++)
			for (int mainKeyLength = 0; mainKeyLength < 3; mainKeyLength++)
				for (int subKeyType = 0; subKeyType < 4; subKeyType++)
					for (int subKeyLength = 0;
						subKeyLength < 3;
						subKeyLength++)
						printEntry(
							mainKeyType,
							mainKeyLength,
							subKeyType,
							subKeyLength);

	}

	public static void printEntry(
		int mainKeyType,
		int mainKeyLength,
		int subKeyType,
		int subKeyLength)
	{
		// Exclusions here

		if (mainKeyType == MAIN_RSA && mainKeyLength == L768)
			return;
		if (mainKeyType == MAIN_RSA_S && mainKeyLength == L768)
			return;
		if (subKeyType == SUB_RSA && subKeyLength == L768)
			return;
		if (subKeyType == SUB_RSA_E && subKeyLength == L768)
			return;

		if (mainKeyType == MAIN_DSA && mainKeyLength == L2048)
			return;

		// As near as I can tell, this always crashes GPG.
		if (subKeyType == SUB_RSA_E)
			return;

		// GPG thinks this is an invalid algorithm.
		if (mainKeyType == MAIN_RSA_S)
			return;

		System.out.println("%echo Main Key");

		switch (mainKeyType)
		{
			case MAIN_RSA :
				System.out.println("%echo RSA");
				System.out.println("Key-Type: RSA");
				break;
			case MAIN_RSA_S :
				System.out.println("%echo RSA-S");
				System.out.println("Key-Type: RSA-S");
				break;
			case MAIN_DSA :
				System.out.println("%echo DSA");
				System.out.println("Key-Type: DSA");
				break;
			case MAIN_ELG :
				System.out.println("%echo ELG");
				System.out.println("Key-Type: ELG");
				break;
			default :
				throw new RuntimeException("Design error");
		}

		switch (mainKeyLength)
		{
			case L768 :
				System.out.println("%echo 768");
				System.out.println("Key-Length: 768");
				break;
			case L1024 :
				System.out.println("%echo 1024");
				System.out.println("Key-Length: 1024");
				break;
			case L2048 :
				System.out.println("%echo 2048");
				System.out.println("Key-Length: 2048");
				break;
			default :
				throw new RuntimeException("Design error");
		}

		System.out.println("%echo Sub Key");

		switch (subKeyType)
		{
			case SUB_RSA :
				System.out.println("%echo RSA");
				System.out.println("Subkey-Type: RSA");
				break;
			case SUB_RSA_E :
				System.out.println("%echo RSA-E");
				System.out.println("Subkey-Type: RSA-E");
				break;
			case SUB_ELG_E :
				System.out.println("%echo ELG-E");
				System.out.println("Subkey-Type: ELG-E");
				break;
			case SUB_ELG :
				System.out.println("%echo ELG");
				System.out.println("Subkey-Type: ELG");
				break;
			default :
				throw new RuntimeException("Design error");
		}

		switch (subKeyLength)
		{
			case 0 :
				System.out.println("%echo 768");
				System.out.println("Subkey-Length: 768");
				break;
			case 1 :
				System.out.println("%echo 1024");
				System.out.println("Subkey-Length: 1024");
				break;
			case 2 :
				System.out.println("%echo 2048");
				System.out.println("Subkey-Length: 2048");
				break;
			default :
				throw new RuntimeException("Design error");
		}

		System.out.println("Name-Real: name");
		System.out.println("Name-Comment: comment");
		System.out.println("Name-Email: " + (n++) + "@test.hush.com");
		System.out.println("Expire-Date: 0");
		System.out.println("Passphrase: test");

		System.out.println("%commit");
	}
}
