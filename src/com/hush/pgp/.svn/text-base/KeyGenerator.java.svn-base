/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.pgp;

import java.security.SecureRandom;
import java.util.Vector;

/**
 * This class generates a complete set of PGP keys.
 * 
 * @author Brian Smith
 */
public class KeyGenerator implements PgpConstants
{
	private SecureRandom random;
	private int symmetricAlgorithm = CIPHER_AES256;
	private int s2kType = S2kAlgorithm.S2K_TYPE_ITERATED_AND_SALTED;
	private int s2kCount = 65536;
	private int signingKeyAlgorithm = CIPHER_RSA;
	private int encryptionKeyAlgorithm = CIPHER_RSA;
	private int hashAlgorithm = HASH_SHA256;
	private int signingKeySize = 1024;
	private int encryptionKeySize = 2048;
	private int version = 4;
	private Vector designatedRevokers = new Vector();

	private Vector preferredHashAlgorithms = new Vector();
	private Vector preferredSymmetricAlgorithms = new Vector();
	private Vector preferredCompressionAlgorithms = new Vector();

	public KeyGenerator(SecureRandom random)
	{
		this.random = random;
	}

	public void addDesignatedRevoker(
		byte[] fingerprint,
		int algorithm,
		boolean sensitive)
	{
		designatedRevokers.addElement(
			new RevocationKeySpecifier(fingerprint, algorithm, sensitive));
	}

	/**
	 * Add the preferred hash algorithms for the key to be generated.
	 * The first algorithm added will have the first preference.
	 * 
	 * @see com.hush.pgp.PgpConstants
	 */
	public void addPreferredHashAlgorithm(int algorithm)
	{
		preferredHashAlgorithms.addElement(new Byte((byte) algorithm));
	}

	/**
	 * Add the preferred symmetric algorithms for the key to be generated.
	 * The first algorithm added will have the first preference.
	 * 
	 * @param algorithm
	 * @see com.hush.pgp.PgpConstants
	 */
	public void addPreferredSymmetricAlgorithm(int algorithm)
	{
		preferredSymmetricAlgorithms.addElement(new Byte((byte) algorithm));
	}

	/**
	 * Add the preferred compression algorithms for the key to be generated.
	 * The first algorithm added will have the first preference.
	 * 
	 * @param algorithm
	 * @see com.hush.pgp.PgpConstants
	 */
	public void addPreferredCompressionAlgorithm(int algorithm)
	{
		preferredCompressionAlgorithms.addElement(new Byte((byte) algorithm));
	}

	public Key generateKey(String userID, byte[] passphrase)
	{
		// First, generate a key pair.
		Key mainKey =
			new Key(
				version,
				System.currentTimeMillis() / 1000,
				signingKeyAlgorithm,
				signingKeySize,
				Key.KeyType.SIGNING,
				random);
		
		mainKey.encryptSecretKeyMaterial(
			passphrase,
			symmetricAlgorithm,
			s2kType,
			hashAlgorithm,
			s2kCount,
			true);

		UserID userIDObj = new UserID();
		userIDObj.setUserID(userID);

		mainKey.addUserID(userIDObj);

		Signature signatureOnUserID = new Signature();
		signatureOnUserID.setHashAlgorithm(hashAlgorithm);
		if (preferredHashAlgorithms.size() > 0)
		{
			byte[] hashAlgoBytes = new byte[preferredHashAlgorithms.size()];
			for (int x = 0; x < preferredHashAlgorithms.size(); x++)
				hashAlgoBytes[x] =
					((Byte) preferredHashAlgorithms.elementAt(x)).byteValue();
			signatureOnUserID.setPreferredHashAlgorithms(
				hashAlgoBytes,
				true,
				false);
		}

		if (preferredSymmetricAlgorithms.size() > 0)
		{
			byte[] symAlgoBytes = new byte[preferredSymmetricAlgorithms.size()];
			for (int x = 0; x < preferredSymmetricAlgorithms.size(); x++)
				symAlgoBytes[x] =
					((Byte) preferredSymmetricAlgorithms.elementAt(x))
						.byteValue();
			signatureOnUserID.setPreferredSymmetricAlgorithms(
				symAlgoBytes,
				true,
				false);
		}

		if (preferredCompressionAlgorithms.size() > 0)
		{
			byte[] symAlgoBytes =
				new byte[preferredCompressionAlgorithms.size()];
			for (int x = 0; x < preferredCompressionAlgorithms.size(); x++)
				symAlgoBytes[x] =
					((Byte) preferredCompressionAlgorithms.elementAt(x))
						.byteValue();
			signatureOnUserID.setPreferredCompressionAlgorithms(
				symAlgoBytes,
				true,
				false);
		}

		userIDObj.sign(
			signatureOnUserID,
			mainKey,
			Signature.SIGNATURE_CERTIFICATION_GENERIC,
			System.currentTimeMillis() / 1000,
			random);
		
		Signature signatureOnMainKey = new Signature();
		signatureOnMainKey.setHashAlgorithm(hashAlgorithm);
		signatureOnMainKey.setRevocable(true, true, false);
		for (int x = 0; x < designatedRevokers.size(); x++)
			signatureOnMainKey.setRevocationKey(
				(RevocationKeySpecifier) designatedRevokers.elementAt(x),
				true,
				false);

		mainKey.sign(
			signatureOnMainKey,
			mainKey,
			Signature.SIGNATURE_DIRECTLY_ON_KEY,
			System.currentTimeMillis() / 1000,
			random);
		
		Key mySubkey =
			new Key(
					version,
					System.currentTimeMillis() / 1000,
					encryptionKeyAlgorithm,
					encryptionKeySize,
					Key.KeyType.ENCRYPTION,
					random);
		mySubkey.encryptSecretKeyMaterial(
				passphrase,
				symmetricAlgorithm,
				s2kType,
				hashAlgorithm,
				s2kCount,
				true);
		mainKey.addSubkey(mySubkey);

		Signature signatureOnSubkey = new Signature();
		signatureOnSubkey.setHashAlgorithm(hashAlgorithm);
		mySubkey.sign(
				signatureOnSubkey,
				mainKey,
				Signature.SIGNATURE_SUBKEY_BINDING,
				System.currentTimeMillis() / 1000,
				random);
		
		return mainKey;
	}
	
	public int getEncryptionKeyAlgorithm()
	{
		return encryptionKeyAlgorithm;
	}
	
	public void setEncryptionKeyAlgorithm(int encryptionKeyAlgorithm)
	{
		this.encryptionKeyAlgorithm = encryptionKeyAlgorithm;
	}
	
	public int getEncryptionKeySize()
	{
		return encryptionKeySize;
	}
	
	public void setEncryptionKeySize(int encryptionKeySize)
	{
		this.encryptionKeySize = encryptionKeySize;
	}
	
	public int getHashAlgorithm()
	{
		return hashAlgorithm;
	}
	
	public void setHashAlgorithm(int hashAlgorithm)
	{
		this.hashAlgorithm = hashAlgorithm;
	}
	
	public int getSigningKeyAlgorithm()
	{
		return signingKeyAlgorithm;
	}
	
	public void setSigningKeyAlgorithm(int signingKeyAlgorithm)
	{
		this.signingKeyAlgorithm = signingKeyAlgorithm;
	}
	
	public int getSigningKeySize()
	{
		return signingKeySize;
	}
	
	public void setSigningKeySize(int signingKeySize)
	{
		this.signingKeySize = signingKeySize;
	}
}
