/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.pgp;

import com.hush.util.Conversions;
import com.hush.util.EmailAddress;
import com.hush.util.Logger;

/**
 * A class that encapsulates a PGP user ID.  A user ID will usually
 * be a UTF-8 string, but it is not restricted to this.
 * 
 * @author Brian Smith 
 */
public class UserID extends Signable
{
	private static final long serialVersionUID = 2412661754623868536L;
	private byte[] userID;

	public void setUserID(byte[] userID)
	{
		this.userID = userID;
	}

	public void setUserID(String userID)
	{
		this.userID = Conversions.stringToByteArray(userID, UTF8);
	}

	public byte[] getBytes()
	{
		return userID;
	}

	/**
	 * The user ID is always UTF-8 if it is text.
	 */
	public String toString()
	{
		return Conversions.byteArrayToString(userID, UTF8);
	}

	/**
	 * This method verifies all the signatures on the user ID by the
	 * given key, and returns all the signatures that verify successfully.
	 * It also checks for revocation signatures, for the given date.
	 * <br>
	 * The array of signatures can then be parsed for information regarding
	 * the verified certification.
	 * 
	 * @param key the signing key
	 * @param time check for validity at this time, in seconds since 1970-01-01 00:00:00; -1 indicates ignore
	 * @return all the signatures that successfully verify
	 */
	public Signature[] verifyCertifications(
		Key key,
		long time,
		boolean dieOnFailure)
		throws InvalidSignatureException
	{
		Signature[] returnValue =
			verifySignatures(
				key,
				new int[] {
					Signature.SIGNATURE_ON_BINARY_DOCUMENT,
					Signature.SIGNATURE_ON_CANONICAL_TEXT,
					Signature.SIGNATURE_STANDALONE,
					Signature.SIGNATURE_CERTIFICATION_GENERIC,
					Signature.SIGNATURE_CERTIFICATION_PERSONA,
					Signature.SIGNATURE_CERTIFICATION_CASUAL,
					Signature.SIGNATURE_CERTIFICATION_POSITIVE },
				time,
				dieOnFailure);
		return returnValue;
	}

	public byte[] getBytesForSignature(int signatureVersion)
	{
		byte[] signableBytes;
		if (signatureVersion < 4)
		{
			signableBytes = getBytes();
		}
		else
		{
			signableBytes = new byte[5 + getBytes().length];
			signableBytes[0] = (byte) 0xb4;
			Conversions.longToBytes(getBytes().length, signableBytes, 1, 4);
			System.arraycopy(
				getBytes(),
				0,
				signableBytes,
				5,
				getBytes().length);
		}
		Logger.hexlog(
			this,
			Logger.DEBUG,
			"User ID bytes for signing: ",
			signableBytes);
		return signableBytes;
	}

	public boolean hasUserID(String userID)
	{
		userID = userID.toLowerCase();
		if (userID.equals(toString().toLowerCase()))
		{
			return true;
		}
		else if (
			EmailAddress
				.parseRecipient(toString())
				.getEmailAddress()
				.toLowerCase()
				.equals(
				userID.toLowerCase()))
		{
			return true;
		}
		return false;
	}

	/**
	 * Compares the user ID with another user ID based only
	 * on the user ID itself, not the attached signatures.
	 * 
	 * @param userID the user ID with which to compare this one
	 * @return true if equivalent, false otherwise
	 */
	public boolean equals(UserID userID)
	{
		return userID.toString().equalsIgnoreCase(toString());
	}
}
