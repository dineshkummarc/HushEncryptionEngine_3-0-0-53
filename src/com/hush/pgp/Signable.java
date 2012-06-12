/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.pgp;

import java.io.Serializable;
import java.security.SecureRandom;
import java.util.Enumeration;
import java.util.Vector;

import com.hush.util.ArrayTools;
import com.hush.util.Conversions;
import com.hush.util.Logger;
import com.hush.util.UnrecoverableKeyException;

/**
 * An abstract class to group objects that have signatures associated 
 * with them.
 * 
 * @author Brian Smith
 */
public abstract class Signable implements PgpConstants, Serializable
{
	private static final long serialVersionUID = -1183427350968400734L;
	
	protected Vector signatures = new Vector();
	protected Signable mainKey = this;

	/**
	 * Adds a signature to the signable entity.
	 * 
	 * @param signature the signature to add
	 */
	public final void addSignature(Signature signature)
	{
		signatures.addElement(signature);
	}

	public abstract byte[] getBytesForSignature(int signatureVersion);

	/**
	 * Returns all the signatures on this object of the specified type
	 * created by a key with the specified key ID.
	 * Note that these signatures may not yet have been verified.
	 * 
	 * Passing -1 as the type will return signatures of all types.
	 * 
	 * Passing null as the key ID will return signatures for all key IDs.
	 * 
	 * @param type the type of signature to return
	 * @param signerKeyID identifies the key that created the signature; null for all
	 * @return an array of signatures
	 */
	public final Signature[] getSignatures(int type, byte[] signerKeyID)
	{
		Vector v = new Vector();
		Enumeration e = signatures.elements();
		Signature sig;
		while (e.hasMoreElements())
		{
			sig = (Signature) e.nextElement();
			if ((type == -1 || sig.getSignatureType() == type)
				&& (signerKeyID == null
					|| ArrayTools.equals(signerKeyID, sig.getIssuerKeyID(false))))
			{
				v.addElement(sig);
			}
		}
		Signature[] sigArray = new Signature[v.size()];
		v.copyInto(sigArray);
		return sigArray;
	}

	/**
	 * Sets the main key of this object. This is 
	 * <br>
	 * You cannot set an object to be it's own parent.
	 * 
	 * @param parent the parent object
	 */
	protected final void setMainKey(Key mainKey)
	{
		this.mainKey = mainKey;
	}

	/**
	 * Gets the parent key of this object.  In the case of a
	 * subkey or user ID, this is the main key.
	 * 
	 * @return the main key associated with this object
	 */
	public final Key getMainKey()
	{
		if (mainKey == this && mainKey instanceof UserID)
			throw new IllegalStateException("The main key of this user ID has not been set");
		return (Key) mainKey;
	}

	/**
	 * This method returns all the signatures by the signer on this 
	 * object that can be verified.
	 * 
	 * @param signer the signer
	 * @param signatureTypes verify signatures of these types; null for all
	 * @param dieOnFailure if <code>true</code>, an exception will be thrown
	 * on a verification failure
	 * @return the verified signatures
	 * @throws PgpException if a signature fails to verify and
	 * <code>dieOnFailure</code> is <code>true</code>
	 */
	public final Signature[] verifySignatures(
		Key signer,
		int[] signatureTypes,
		long time,
		boolean dieOnFailure)
		throws InvalidSignatureException
	{
		Enumeration e = signatures.elements();
		Signature sig;
		Vector verified = new Vector();
		while (e.hasMoreElements())
		{
			sig = (Signature) e.nextElement();

			if (ArrayTools.equals(sig.getIssuerKeyID(false), signer.getKeyID())
				|| ArrayTools.equals(sig.getIssuerKeyID(false), WILD_CARD_KEY_ID))
			{

				boolean isTypeToVerify = (signatureTypes == null);

				for (int x = 0;
					isTypeToVerify == false && x < signatureTypes.length;
					x++)
				{
					isTypeToVerify =
						(sig.getSignatureType() == signatureTypes[x]);
				}

				if (isTypeToVerify)
				{
					sig.startVerification();

					// If there is a main key, generate the signature over
					// it before its child.
					if (getMainKey() != this)
					{
						sig.update(
							getMainKey().getBytesForSignature(
								sig.getVersion()));
					}

					// Generate the signature over this object
					sig.update(getBytesForSignature(sig.getVersion()));

					if (this instanceof Key)
					{
						Logger.hexlog(
							this,
							Logger.DEBUG,
							"Verifying signature of type "
								+ sig.getSignatureType()
								+ " on "
								+ Conversions.bytesToHexString(
									((Key) this).getKeyID())
								+ " by ",
							signer.getKeyID());

					}
					else if (this instanceof UserID)
					{
						Logger.hexlog(
							this,
							Logger.DEBUG,
							"Verifying signature of type "
								+ sig.getSignatureType()
								+ " on "
								+ toString()
								+ " by ",
							signer.getKeyID());

					}

					try
					{
						sig.finishVerification(signer);
						try
						{
							if (time != 0)
								sig.checkValidity(time);
							verified.addElement(sig);
						}
						catch (SignatureExpiredException sEE)
						{
							Logger
									.logThrowable(
											this,
											Logger.WARNING,
											"Expiration error during verification",
											sEE);
						}
					}
					catch (InvalidSignatureException iSE)
					{
						if (dieOnFailure)
							throw iSE;
					}
				}
			}
		}
		Signature[] returnArray = new Signature[verified.size()];
		verified.copyInto(returnArray);
		return returnArray;
	}

	/**
	 * Computes the signature and adds it to the signatures on this object.
	 * Set any flags on the signature you want before computing it.
	 * <br>
	 * 
	 * @param signature the signture to be added
	 * @param signer the private key with which to create the signature
	 * @param signatureType the type of signature to generate
	 * @param creationTime the creation time in seconds since 1970-01-01 00:00:00 GMT
	 * @throws PgpException if the secret key cannot be accessed
	 */
	public void sign(
		Signature signature,
		Key signer,
		int signatureType,
		long creationTime,
		SecureRandom random)
		throws UnrecoverableKeyException
	{
		signature.startSigning(signer, signatureType, creationTime);
		// If there is a main key, generate the signature over
		// it before its child.
		if (getMainKey() != this)
		{
			signature.update(
				getMainKey().getBytesForSignature(signature.getVersion()));
		}
		signature.update(getBytesForSignature(signature.getVersion()));
		signature.finishSigning(random);		
		addSignature(signature);
	}

	/**
	 * Removes the specified signature from the object.
	 * 
	 * @param signature the signature to remove
	 */
	public void removeSignature(Signature signature)
	{
		while (signatures.removeElement(signature))
		{
		}
	}

	/**
	 * Returns any revocation signatures found on the object or its main key.
	 * It does not verify the signatures.
	 * 
	 * @param signerKeyID return only signatures by this signer
	 */
	public Signature[] getRevocationSignatures(byte[] signerKeyID)
	{
		int revocationType;
		if (mainKey == getMainKey())
			revocationType = Signature.SIGNATURE_KEY_REVOCATION;
		else if (this instanceof Key)
			revocationType = Signature.SIGNATURE_SUBKEY_REVOCATION;
		else
			revocationType = Signature.SIGNATURE_CERTIFICATION_REVOCATION;
		return getSignatures(revocationType, signerKeyID);
	}

	/**
	 * Checks to see if there are any revocation signatures on either this object
	 * or it's main key.  It does not verify the signatures.
	 */
	public boolean isRevoked()
	{
		if (this == getMainKey())
			return getRevocationSignatures(null).length > 0;
		return getMainKey().isRevoked()
			|| getRevocationSignatures(null).length > 0;
	}
}
