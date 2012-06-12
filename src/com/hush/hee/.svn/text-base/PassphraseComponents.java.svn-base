package com.hush.hee;

import java.security.SecureRandom;

import com.hush.util.Conversions;
import com.hush.util.UnrecoverableKeyException;

public class PassphraseComponents
{

	// Index for shadows in secret sharing algorithm.
	public static final int HUSH_SHADOW = 0;

	// Index for shadows in secret sharing algorithm.
	public static final int CUSTOMER_SHADOW = 1;

	// Index for shadows in secret sharing algorithm.
	public static final int USER_SHADOW = 2;

	public static String[] makeShadows(byte[] passphraseBytes,
			SecureRandom random)
	{
		LineInterpolation secretSharingAlgorithm = new LineInterpolation();

		// 
		secretSharingAlgorithm.setRandom(random);

		secretSharingAlgorithm.generate(passphraseBytes);

		byte[] hush_shadow = secretSharingAlgorithm
				.getEncodedShadow(HUSH_SHADOW);
		byte[] user_shadow = secretSharingAlgorithm
				.getEncodedShadow(USER_SHADOW);
		byte[] customer_shadow = secretSharingAlgorithm
				.getEncodedShadow(CUSTOMER_SHADOW);

		return new String[]
		{ Conversions.bytesToHexString(hush_shadow),
				Conversions.bytesToHexString(user_shadow),
				Conversions.bytesToHexString(customer_shadow) };
	}
}
