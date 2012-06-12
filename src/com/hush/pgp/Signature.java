/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.pgp;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PushbackInputStream;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.DSAKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.DSASigner;

import com.hush.pgp.io.ArmorInputStream;
import com.hush.pgp.io.ArmorOutputStream;
import com.hush.pgp.io.packets.PacketInputStream;
import com.hush.pgp.io.packets.PacketOutputStream;
import com.hush.pgp.io.packets.SignatureInputStream;
import com.hush.pgp.io.packets.SignatureOutputStream;
import com.hush.util.ArrayTools;
import com.hush.util.Conversions;
import com.hush.util.ExceptionWrapper;
import com.hush.util.Logger;
import com.hush.util.UnrecoverableKeyException;

/**
 * A class to create and verify PGP signatures.
 *
 * @author Brian Smith
 */
public class Signature extends Signable implements PgpConstants
{
	private static final long serialVersionUID = 6423719287704486896L;
	private static final int STATUS_NEUTRAL = 0;
	private static final int STATUS_SIGNING = 1;
	private static final int STATUS_VERIFYING = 2;

	/**
	 * Loads one or more detached signatures from a stream.
	 * <br>
	 * The signatures may be armored or unarmored																									 * 
	 * @param in the stream from which the signature is loaded
	 */
	public static Signature[] load(InputStream in)
		throws DataFormatException, IOException
	{
		return load(in, null, false);
	}
	
	/**
	 * Loads one or more detached signatures from a stream.
	 * <br>
	 * The signatures may be armored or unarmored																									 * 
	 * @param a String containing signature(s)
	 */
	public static Signature[] load(String in)
		throws DataFormatException, IOException
	{
		return load(in.getBytes(UTF8));
	}
	
	/**
	 * Loads one or more detached signatures from a stream. <br>
	 * The signatures may be armored or unarmored.
	 * 
	 * @param a byte array containing the signature
	 */
	public static Signature[] load(byte[] in) throws DataFormatException,
			IOException
	{
		return load(new ByteArrayInputStream(in));
	}
	
	/**
	 * Loads one or more detached signatures from a stream.
	 * 
	 * Character encodings only matter if you will be passing strings into
	 * the update calls.  For bytes, it won't matter.
	 * 
	 * <br>
	 * The signatures may be armored or unarmored																									 * 
	 * @param in the stream from which the signature is loaded
	 * @param the default character encoding to use if no character encoding
	 *  is found in the signature headers
	 * @param even if a character encoding is found in the headers, override it
	 *  with the default
	 */
	public static Signature[] load(InputStream in, String defaultCharacterEncoding,
			boolean overrideHeaderCharacterEncoding)
		throws DataFormatException, IOException
	{
		Vector sigs = new Vector();
		PushbackInputStream tempIn = new PushbackInputStream(in, 1);
		int firstCharacter = tempIn.read();
		tempIn.unread(firstCharacter);
		InputStream sigIn;
		if (firstCharacter == (int) '-')
			sigIn = new ArmorInputStream(tempIn);
		else
			sigIn = tempIn;
		PacketInputStream packet = new PacketInputStream(sigIn);
		while (packet.getType() == PACKET_TAG_SIGNATURE)
		{
			Signature sig = new SignatureInputStream(packet).getSignature();
			String charset = null;
			if ( sigIn instanceof ArmorInputStream )
			{
				charset = ((ArmorInputStream)sigIn).getCharacterEncoding();
			}
			if ( defaultCharacterEncoding != null && overrideHeaderCharacterEncoding )
			{
				sig.setCharacterEncoding(defaultCharacterEncoding);
			}
			else if ( charset != null )
			{
				sig.setCharacterEncoding(charset);
			}
			else if ( defaultCharacterEncoding != null )
			{
				sig.setCharacterEncoding(defaultCharacterEncoding);
			}
			sigs.addElement(sig);
			packet = new PacketInputStream(sigIn);
		}
		Signature[] retVal = new Signature[sigs.size()];
		sigs.copyInto(retVal);
		return retVal;
	}

	public static String toString(Signature[] signatures, Hashtable headers)
	{
		try
		{
			ByteArrayOutputStream b = new ByteArrayOutputStream();
			ArmorOutputStream armorStream =
				new ArmorOutputStream(b, ARMOR_TYPE_PGP_SIGNATURE);
			if (headers != null)
				armorStream.setHeaders(headers);
			for (int x = 0; x < signatures.length; x++)
			{
				if (signatures[x].getCharacterEncoding() != null)
				{
					armorStream.setCharacterEncoding(signatures[x]
							.getCharacterEncoding());
				}
			}
			for (int x = 0; x < signatures.length; x++)
			{
				armorStream.write(signatures[x].getBytes(false, null));
			}
			armorStream.close();
			return Conversions.byteArrayToString(b.toByteArray(), UTF8);
		}
		catch (IOException e)
		{
			// We don't expect this will happen, since we're only reading
			// from data that we already have.
			throw ExceptionWrapper.wrapInRuntimeException("Should never happen", e);
		}
	}
	private String characterEncoding = UTF8;

	private long creationTime;

	// Hash algorithm defaults to SHA1.  (If it is a DSA sig,
	// it will always be forced to SHA1.
	private int hashAlgorithm = HASH_SHA1;
	//private boolean hashAlgorithmIsOnDefault = true;

	private Vector hashedSubpackets = new Vector();
	private byte[] issuerKeyID;

	// These are variable used to store info during signing or verification.
	// Used only between start and finish, so they do not need to persist.
	transient private CipherParameters key;
	transient private Digest digest;
	
	private byte[] leftSixteenBitsOfHash;
	private MPI[] mpis;
	private int publicKeyAlgorithm;
	private int signatureType;
	private int status = STATUS_NEUTRAL;
	private Vector unhashedSubpackets = new Vector();

	// Version defaults to 4.
	private int version = 4;

	private void addSubpacket(
		int type,
		byte[] data,
		boolean definitive,
		boolean critical)
	{
		SignatureSubpacket subpacket =
			new SignatureSubpacket(type, data, critical);
		if (definitive)
			hashedSubpackets.addElement(subpacket);
		else
			unhashedSubpackets.addElement(subpacket);
	}

	/**
	 * Adds a subpacket to the signature.
	 * 
	 * @param sign sign the subpacket
	 */
	public void addSubpacket(SignatureSubpacket subpacket, boolean sign)
	{
		if (sign)
			hashedSubpackets.addElement(subpacket);
		else
			unhashedSubpackets.addElement(subpacket);
	}

	/**
	 * Checks to see if this signature was valid at the specified time.
	 */
	public void checkValidity(long time) throws SignatureExpiredException
	{
		Logger.log(
			this,
			Logger.DEBUG,
			"Checking signature validity at: " + time);
		long creationTime = getCreationTime(true);
		Logger.log(this, Logger.DEBUG, "Creation time: " + creationTime);
		if (creationTime > time)
		{
			Logger.log(
				this,
				Logger.WARNING,
				"The signature was created after the given time");
			return;
		}
		long expirationTime = getSignatureExpirationTime(true);
		Logger.log(this, Logger.DEBUG, "Expiration time: " + expirationTime);
		if (expirationTime > 0 && creationTime + expirationTime < time)
		{
			throw new SignatureExpiredException("The signature expired before the given time");
		}
	}

	/**
	 * Finish the signature creation procedure.
	 * 
	 * @throws java.lang.IllegalStateException if signing is not in progress
	 * @throws java.lang.IllegalArgumentException if the public key algorithm is not supported
	 */
	public void finishSigning(SecureRandom random)
	{
		Logger.log(this, Logger.DEBUG, "Finishing signature");
		if (status == STATUS_VERIFYING)
			throw new IllegalStateException("Cannot perform this action during verification");
		if (status == STATUS_NEUTRAL)
			throw new IllegalStateException("Please start signing first");
		byte[] signedBytes = getSignedBytes();
		digest.update(signedBytes, 0, signedBytes.length);
		if (getVersion() == 4)
		{
			digest.update((byte) 0x04);
			digest.update((byte) 0xFF);
			digest.update(Conversions.longToBytes(signedBytes.length, 4), 0, 4);
		}
		byte[] digestResult = new byte[HASH_LENGTHS[getHashAlgorithm()]];
		digest.doFinal(digestResult, 0);
		Logger.hexlog(
			this,
			Logger.DEBUG,
			"Digest result for signing: ",
			digestResult);
		digest = null;
		byte[] leftSixteenBitsOfHash = new byte[2];
		System.arraycopy(digestResult, 0, leftSixteenBitsOfHash, 0, 2);
		setLeftSixteenBitsOfHash(leftSixteenBitsOfHash);
		BigInteger[] sigBigInts;
		switch (getPublicKeyAlgorithm())
		{
			case CIPHER_DSA :
				DSASigner dsaSigner = new DSASigner();
				dsaSigner.init(true, new ParametersWithRandom(key, random));
				sigBigInts = dsaSigner.generateSignature(digestResult);
				break;
			case CIPHER_RSA :
			case CIPHER_RSA_SIGN_ONLY :
				byte[] inputForSignature =
					new byte[digestResult.length
						+ RSA_SIGNATURE_HASH_PREFIXES[getHashAlgorithm()].length];
				System.arraycopy(
					RSA_SIGNATURE_HASH_PREFIXES[getHashAlgorithm()],
					0,
					inputForSignature,
					0,
					inputForSignature.length - digestResult.length);
				System.arraycopy(
					digestResult,
					0,
					inputForSignature,
					inputForSignature.length - digestResult.length,
					digestResult.length);
				PKCS1Encoding rsaCipher = new PKCS1Encoding(new RSAEngine());
				rsaCipher.init(true, key);
				try
				{
					byte[] rawSignature =
						rsaCipher.processBlock(
							inputForSignature,
							0,
							inputForSignature.length);

					sigBigInts = new BigInteger[1];
					sigBigInts[0] = new BigInteger(1, rawSignature);
				}
				catch (InvalidCipherTextException e)
				{
					throw new RuntimeException("Caught InvalidCipherTextException. This should never happen.");
				}
				break;
			default :
				throw new IllegalArgumentException(
					"Unsupported public key algorithm: "
						+ getPublicKeyAlgorithm());
		}
		MPI[] sigMPIs = new MPI[sigBigInts.length];
		for (int x = 0; x < sigMPIs.length; x++)
			sigMPIs[x] = new MPI(sigBigInts[x]);
		setSignatureMPIs(sigMPIs);
		status = STATUS_NEUTRAL;
	}

	/**
	 * Finished the signature verification procedure.
	 *
	 * @param publicKey the key with which to verify the signature.
	 * @throws java.lang.IllegalStateException if signing is not in progress
	 * @throws com.hush.pgp.InvalidSignatureException if the signature verification fails
	 * @throws java.lang.IllegalArgumentException if the public key algorithm is not supported
	 */
	public void finishVerification(Key publicKey)
		throws InvalidSignatureException
	{
		if (status == STATUS_SIGNING)
			throw new IllegalStateException("Cannot perform this action during signing");
		if (status == STATUS_NEUTRAL)
			throw new IllegalStateException("Please start verification first");

		byte[] signedBytes = getSignedBytes();
		digest.update(signedBytes, 0, signedBytes.length);
		if (getVersion() == 4)
		{
			digest.update((byte) 0x04);
			digest.update((byte) 0xFF);
			digest.update(Conversions.longToBytes(signedBytes.length, 4), 0, 4);
		}
		byte[] digestResult = new byte[HASH_LENGTHS[getHashAlgorithm()]];
		digest.doFinal(digestResult, 0);
		Logger.hexlog(this, Logger.DEBUG, "Hash result: ", digestResult);

		if (!ArrayTools
			.equals(getLeftSixteenBitsOfHash(), 0, digestResult, 0, 2))
		{
			Logger.log(this, Logger.DEBUG, "Wrong hash for verification");
			throw new InvalidSignatureException("Hash of data does not match hash in signature packet");
		}
		else
		{
			CipherParameters cipherParameters = publicKey.getPublicKey();
			switch (getPublicKeyAlgorithm())
			{
				case CIPHER_DSA :
					if (!(cipherParameters instanceof DSAKeyParameters))
					throw new InvalidSignatureException(
							"Need DSA key to verify DSA signature");
					DSASigner dsaSigner = new DSASigner();
					dsaSigner.init(false, cipherParameters);
					if (!dsaSigner
						.verifySignature(
							digestResult,
							mpis[0].getBigInteger(),
							mpis[1].getBigInteger()))
						throw new InvalidSignatureException();
					break;
				case CIPHER_RSA :
				case CIPHER_RSA_SIGN_ONLY :
					if (!(cipherParameters instanceof RSAKeyParameters))
					throw new InvalidSignatureException(
							"Need RSA key to verify RSA signature");
					PKCS1Encoding cipher = new PKCS1Encoding(new RSAEngine());
					cipher.init(false, cipherParameters);
					byte[] cipherText =
						Conversions.bigIntegerToUnsignedBytes(
							mpis[0].getBigInteger());
					try
					{
						byte[] decryptedBytes =
							cipher.processBlock(
								cipherText,
								0,
								cipherText.length);
						// Note: we are just ignoring all the ASN.1 information
						// at the beginning of the decrypted value. -sbs
						if (
							decryptedBytes.length < digestResult.length	||
							!ArrayTools
							.equals(
								digestResult,
								0,
								decryptedBytes,
								decryptedBytes.length - digestResult.length,
								digestResult.length))
							throw new InvalidSignatureException("Computed signature does not match signature in signature packet");
					}
					catch (InvalidCipherTextException e)
				{
					throw InvalidSignatureException.wrap(
							"Signature cipher text invalid", e);
				}
					break;
				default :
					throw new IllegalArgumentException(
						"Unsupported public key algorithm: "
							+ getPublicKeyAlgorithm());
			}
		}
		status = STATUS_NEUTRAL;
	}

	public byte[] getBytes(boolean armor, Hashtable headers)
	{
		try
		{

			ByteArrayOutputStream b = new ByteArrayOutputStream();
			OutputStream toWriteTo;
			if (armor)
			{
				ArmorOutputStream armorStream =
					new ArmorOutputStream(b, ARMOR_TYPE_PGP_SIGNATURE);
				if (headers != null)
					armorStream.setHeaders(headers);
				armorStream.setCharacterEncoding(characterEncoding);
				toWriteTo = armorStream;
			}
			else
				toWriteTo = b;
			SignatureOutputStream s;
			s =
				new SignatureOutputStream(
					new PacketOutputStream(toWriteTo),
					this);
			s.close();
			toWriteTo.close();
			return b.toByteArray();
		}
		catch (IOException e)
		{
			// We don't expect this will happen, since we're only reading
			// from data that we already have.
			throw ExceptionWrapper.wrapInRuntimeException("Should never happen", e);
		}
	}
	
	public String getCharacterEncoding()
	{
		if (characterEncoding == null
				|| characterEncoding.equals(UTF8_ALTERNATE))
				return UTF8;
			return characterEncoding;
	}

	/**
	 * Returns the signature creation time from the hashed section
	 * of the packet.  Returns -1 if not specified.
	 * <br>
	 * RFC 2440 5.2.3.4 ( 5.2.2 for V3 signatures )
	 * 
	 * @param definitive required the data to be signed
	 */
	public long getCreationTime(boolean definitive)
	{
		if (version < 4)
			return creationTime;
		byte[] timeBytes =
			getSubpacketData(
				SignatureSubpacket.TYPE_SIGNATURE_CREATION_TIME,
				definitive);
		if (timeBytes == null)
			return -1;
		return Conversions.bytesToLong(timeBytes);
	}

	/**
	 * Returns true if the certification implied by the signature
	 * is exportable.  Won't apply to all types of signatures.
	 * Defaults to true.
	 * <br>
	 * RFC 2440 5.2.3.11
	 * 
	 * @param definitive require the data to be signed
	 */
	public boolean getExportableCertification(boolean definitive)
	{
		byte[] exportable =
			getSubpacketData(
				SignatureSubpacket.TYPE_EXPORTABLE_CERTIFICATION,
				definitive);
		if (exportable == null)
			return true;
		return exportable[0] == 1;
	}

	/**
	 * Returns information on features that a user's implementation supports.
	 * <br>
	 * RFC 2440 5.2.3.24
	 *
	 * @param definitive require the data to be signed
	 */
	public Features getFeatures(boolean definitive)
	{
		byte[] features =
			getSubpacketData(SignatureSubpacket.TYPE_FEATURES, definitive);
		return features == null ? null : new Features(features);
	}

	/**
	 * Returns the public key algorithm.
	 */
	public int getHashAlgorithm()
	{
		return hashAlgorithm;
	}

	/**
	 * Returns the hashed subpackets.
	 */
	public SignatureSubpacket[] getHashedSubpackets()
	{
		SignatureSubpacket[] retVal =
			new SignatureSubpacket[hashedSubpackets.size()];
		hashedSubpackets.copyInto(retVal);
		return retVal;
	}

	/**
	 * Returns the issuer key ID.
	 * <br>
	 * RFC 2440 5.2.3.5 ( 5.2.2 for V3 signatures )
	 * 
	 * @param definitive require the data to be signed
	 */
	public byte[] getIssuerKeyID(boolean definitive)
	{
		if (version != 4)
		{
			if (definitive)
				return null;
			return issuerKeyID;
		}
		return getSubpacketData(
			SignatureSubpacket.TYPE_ISSUER_KEY_ID,
			definitive);
	}

	/**
	 * Returns the key expiration time from the packet.
	 * Returns -1 if not specified.
	 * <br>
	 * RFC 2440 5.2.3.6
	 * 
	 * @param definitive require the data to be signed
	 */
	public long getKeyExpirationTime(boolean definitive)
	{
		byte[] timeBytes =
			getSubpacketData(
				SignatureSubpacket.TYPE_KEY_EXPIRATION_TIME,
				definitive);
		if (timeBytes == null)
			return -1;
		return Conversions.bytesToLong(timeBytes);
	}

	/**
	 * Returns the key flags.
	 * <br>
	 * RFC 2440 5.2.3.21
	 *
	 * @param definitive require the data to be signed
	 */
	public KeyFlags getKeyFlags(boolean definitive)
	{
		byte[] flags =
			getSubpacketData(SignatureSubpacket.TYPE_KEY_FLAGS, definitive);
		return flags == null ? null : new KeyFlags(flags);
	}

	/**
	 * Returns the key server preferences.
	 * <br>
	 * RFC 2440 5.2.3.17
	 *
	 * @param definitive require the data to be signed
	 */
	public KeyServerPreferences getKeyServerPreferences(boolean definitive)
	{
		byte[] prefBytes =
			getSubpacketData(SignatureSubpacket.TYPE_KEY_FLAGS, definitive);
		return prefBytes == null ? null : new KeyServerPreferences(prefBytes);
	}

	/**
	 *  Gets the left sixteen bits of the hash.
	 */
	public byte[] getLeftSixteenBitsOfHash()
	{
		return leftSixteenBitsOfHash;
	}

	/**
	 * Returns any any notation data information.
	 * <br>
	 * RFC 2440 5.2.3.16
	 *
	 * @param definitive require the data to be signed
	 */
	public NotationData[] getNotationData(boolean definitive)
	{
		Vector subpackets =
			getSubpacketVector(
				SignatureSubpacket.TYPE_NOTATION_DATA,
				definitive);
		NotationData[] returnArray = new NotationData[subpackets.size()];
		for (int x = 0; x < returnArray.length; x++)
		{
			returnArray[x] = new NotationData((byte[]) subpackets.elementAt(x));
		}
		return returnArray;
	}

	/**
	 * Returns a URL to the policy under which this key was issued.
	 * <br>
	 * RFC 2440 5.2.3.20
	 *
	 * @param definitive require the data to be signed
	 */
	public byte[] getPolicyURL(boolean definitive)
	{
		return getSubpacketData(SignatureSubpacket.TYPE_POLICY_URL, definitive);
	}

	/**
	 * Returns the preferred compression algorithms from the hashed section of the
	 * packet.
	 * <br>
	 * RFC 2440 5.2.3.9
	 * 
	 * @param definitive require the data to be signed
	 */
	public byte[] getPreferredCompressionAlgorithms(boolean definitive)
	{
		return getSubpacketData(
			SignatureSubpacket.TYPE_PREFERRED_COMPRESSION_ALGORITHMS,
			definitive);
	}

	/**
	 * Returns the preferred hash algorithms from the hashed section of the
	 * packet.
	 * <br>
	 * RFC 2440 5.2.3.8
	 * 
	 * @param definitive require the data to be signed
	 */
	public byte[] getPreferredHashAlgorithms(boolean definitive)
	{
		return getSubpacketData(
			SignatureSubpacket.TYPE_PREFERRED_HASH_ALGORITHMS,
			definitive);
	}

	/**
	 * Returns the preferred key server for this key.
	 * <br>
	 * RFC 2440 5.2.3.18
	 *
	 * @param definitive require the data to be signed
	 */
	public byte[] getPreferredKeyServer(boolean definitive)
	{
		return getSubpacketData(
			SignatureSubpacket.TYPE_PREFERRED_KEY_SERVER,
			definitive);
	}

	/**
	 * Returns the preferred symmetric algorithms from the hashed section of the
	 * packet.
	 * <br>
	 * RFC 2440 5.2.3.7
	 * 
	 * @param definitive require the data to be signed
	 */
	public byte[] getPreferredSymmetricKeyAlgorithms(boolean definitive)
	{
		return getSubpacketData(
			SignatureSubpacket.TYPE_PREFERRED_SYMMETRIC_ALGORITHMS,
			definitive);
	}

	/**
	 * Returns true if the user ID packet to which this signature applies
	 * is the primary user ID for this key.
	 * Won't apply to all types of signatures.
	 * Defaults to false.
	 * <br>
	 * RFC 2440 5.2.3.19
	 * 
	 * @param definitive require the data to be signed
	 */
	public boolean getPrimaryUserID(boolean definitive)
	{
		byte[] primary =
			getSubpacketData(
				SignatureSubpacket.TYPE_PRIMARY_USER_ID,
				definitive);
		if (primary == null)
			return false;
		return primary[0] == 1;
	}

	/**
	 * Returns the public key algorithm.
	 */
	public int getPublicKeyAlgorithm()
	{
		return publicKeyAlgorithm;
	}

	/**
	 * Returns the reason for revocation.  Only applies to revocation signatures.
	 * <br>
	 * RFC 2440 5.2.3.23
	 *
	 * @param definitive require the data to be signed
	 */
	public RevocationReason getReasonForRevocation(boolean definitive)
	{
		byte[] reason =
			getSubpacketData(
				SignatureSubpacket.TYPE_REASON_FOR_REVOCATION,
				definitive);
		return reason == null ? null : new RevocationReason(reason);
	}

	/**
	 * Returns the regular expression used to limit user ID's to which the
	 * trust signature applies.
	 * <br>
	 * RFC 2440 5.2.3.14
	 *
	 * @param definitive require the data to be signed
	 */
	public byte[] getRegularExpression(boolean definitive)
	{
		return getSubpacketData(
			SignatureSubpacket.TYPE_REGULAR_EXPRESSION,
			definitive);
	}

	/**
	 * Returns true if the certification implied by the signature
	 * is revocable.  Won't apply to all types of signatures.
	 * Defaults to true.
	 * <br>
	 * RFC 2440 5.2.3.12
	 * 
	 * @param definitive require the data to be signed
	 */
	public boolean getRevocable(boolean definitive)
	{
		byte[] revocable =
			getSubpacketData(SignatureSubpacket.TYPE_REVOCABLE, definitive);
		if (revocable == null)
			return true;
		return revocable[0] == 1;
	}

	/**
	 * Returns any any revocation key information.
	 * <br>
	 * RFC 2440 5.2.3.15
	 *
	 * @param definitive require the data to be signed
	 */
	public RevocationKeySpecifier[] getRevocationKeys(boolean definitive)
	{
		Vector subpackets =
			getSubpacketVector(
				SignatureSubpacket.TYPE_REVOCATION_KEY,
				definitive);
		RevocationKeySpecifier[] returnArray =
			new RevocationKeySpecifier[subpackets.size()];
		for (int x = 0; x < returnArray.length; x++)
		{
			returnArray[x] =
				new RevocationKeySpecifier((byte[]) subpackets.elementAt(x));
		}
		return returnArray;
	}

	/**
	 * Returns information on the signature to which the signature applies.
	 * Only applies to signatures on signatures.
	 * <br>
	 * RFC 2440 5.2.3.25
	 * 
	 * @param definitive require the data to be signed
	 */
	public SignatureTarget getSignatureTarget(boolean definitive)
	{
		byte[] target =
			getSubpacketData(
				SignatureSubpacket.TYPE_SIGNATURE_TARGET,
				definitive);
		return target == null ? null : new SignatureTarget(target);
	}

	/**
	 * Returns the key expiration time from the packet in number of
	 * seconds since the signature creation.
	 * Returns -1 if not specified.
	 * <br>
	 * RFC 2440 5.2.3.10
	 * 
	 * @param definitive require the data to be signed
	 */
	public long getSignatureExpirationTime(boolean definitive)
	{
		byte[] timeBytes =
			getSubpacketData(
				SignatureSubpacket.TYPE_SIGNATURE_EXPIRATION_TIME,
				definitive);
		if (timeBytes == null)
			return -1;
		return Conversions.bytesToLong(timeBytes);
	}

	/**
	 * Returns the MPI's that make up the actual signature.
	 */
	public MPI[] getSignatureMPIs()
	{
		return mpis;
	}

	/**
	 * Returns the signature type.
	 */
	public int getSignatureType()
	{
		return signatureType;
	}

	/**
	 * Returns the portion of this signature packet that was hashed
	 * when the signature it contains was computed.
	 */
	public byte[] getSignedBytes()
	{
		try
		{
			ByteArrayOutputStream signedBytes = new ByteArrayOutputStream();
			if (version >= 4)
			{
				signedBytes.write(getVersion());
				signedBytes.write(getSignatureType());
				signedBytes.write(getPublicKeyAlgorithm());
				signedBytes.write(getHashAlgorithm());
				int hashedSubpacketsLength = 0;
				ByteArrayOutputStream hashedSubpacketData =
					new ByteArrayOutputStream();
				Enumeration e = hashedSubpackets.elements();
				while (e.hasMoreElements())
				{
					byte[] subpacketBytes =
						((SignatureSubpacket) e.nextElement()).getBytes();
					hashedSubpacketsLength += subpacketBytes.length;
					hashedSubpacketData.write(subpacketBytes);
				}
				byte[] hashedSubpacketsLengthBytes = new byte[2];
				Conversions.longToBytes(
					hashedSubpacketsLength,
					hashedSubpacketsLengthBytes,
					0,
					2);
				signedBytes.write(hashedSubpacketsLengthBytes);
				signedBytes.write(hashedSubpacketData.toByteArray());
			}
			else
			{
				signedBytes.write(getSignatureType());
				byte[] creationTimeBytes = new byte[4];
				Conversions.longToBytes(
					getCreationTime(false),
					creationTimeBytes,
					0,
					4);
				signedBytes.write(creationTimeBytes);
			}
			byte[] signedBytesArray = signedBytes.toByteArray();
			Logger.hexlog(
				this,
				Logger.DEBUG,
				"Signature packet bytes to hash: ",
				signedBytesArray);
			return signedBytesArray;
		}
		catch (IOException e)
		{
			throw new RuntimeException();
		}
	}

	/**
	 * Returns the user ID of the signer.
	 * <br>
	 * RFC 2440 5.2.3.22
	 *
	 * @param definitive require the data to be signed
	 */
	public byte[] getSignersUserID(boolean definitive)
	{
		return getSubpacketData(
			SignatureSubpacket.TYPE_SIGNERS_USER_ID,
			definitive);
	}

	/**
	 * This method returns the data from the most recent
	 * subpacket of the specified type.
	 *
	 * @param definitive if this is true, ignore unsigned subpackets
	 */
	private byte[] getSubpacketData(int type, boolean definitive)
	{
		Enumeration e;
		SignatureSubpacket returnSubpacket = null;
		SignatureSubpacket currentSubpacket;
		e = hashedSubpackets.elements();
		while (e.hasMoreElements())
		{
			currentSubpacket = (SignatureSubpacket) e.nextElement();
			if (currentSubpacket.getType() == type)
				returnSubpacket = currentSubpacket;
		}
		if (!definitive)
		{
			e = unhashedSubpackets.elements();
			while (e.hasMoreElements())
			{
				currentSubpacket = (SignatureSubpacket) e.nextElement();
				if (currentSubpacket.getType() == type)
					returnSubpacket = currentSubpacket;
			}
		}
		return returnSubpacket == null ? null : returnSubpacket.getData();
	}

	/**
	 * This method returns the data from all the subpackets
	 * of the specified type.
	 *
	 * @param definitive if this is true, ignore unsigned subpackets
	 */
	private Vector getSubpacketVector(int type, boolean definitive)
	{
		Enumeration e;
		SignatureSubpacket currentSubpacket;
		Vector returnVector = new Vector();
		e = hashedSubpackets.elements();
		while (e.hasMoreElements())
		{
			currentSubpacket = (SignatureSubpacket) e.nextElement();
			if (currentSubpacket.getType() == type)
				returnVector.addElement(currentSubpacket.getData());
		}
		if (!definitive)
		{
			e = unhashedSubpackets.elements();
			while (e.hasMoreElements())
			{
				currentSubpacket = (SignatureSubpacket) e.nextElement();
				if (currentSubpacket.getType() == type)
					returnVector.addElement(currentSubpacket.getData());
			}
		}
		return returnVector;
	}

	/**
	 * Returns the level of trust the signature associates with a key.
	 * Returns -1 if no data is found.
	 * <br>
	 * RFC 2440 5.2.3.13
	 * 
	 * @param definitive require the data to be signed
	 */
	public int getTrustSignature(boolean definitive)
	{
		byte[] trust =
			getSubpacketData(
				SignatureSubpacket.TYPE_TRUST_SIGNATURE,
				definitive);
		if (trust == null)
			return -1;
		return trust[0];
	}

	/**
	 * Returns the unhashed subpackets.
	 */
	public SignatureSubpacket[] getUnhashedSubpackets()
	{
		SignatureSubpacket[] retVal =
			new SignatureSubpacket[unhashedSubpackets.size()];
		unhashedSubpackets.copyInto(retVal);
		return retVal;
	}

	/**
	 * Returns the version, either 2, 3 or 4.
	 */
	public int getVersion()
	{
		return version;
	}

	/**
	 * Removes the specified subpacket from the signature.
	 * 
	 * @param subpacket the subpacket to remove.
	 */
	public void removeSubpacket(SignatureSubpacket subpacket)
	{
		while (hashedSubpackets.removeElement(subpacket))
		{
		}
		while (unhashedSubpackets.removeElement(subpacket))
		{
		}
	}

	/**
	 * Sets the character encoding to use for text canonicalization.
	 * 
	 * @param encoding the encoding to use
	 * @throws UnsupportedEncodingException if the encoding is not valid
	 */
	public void setCharacterEncoding(String encoding)
		throws UnsupportedEncodingException
	{
		if (encoding != null)
			Conversions.checkCharacterEncoding(encoding);
		this.characterEncoding = encoding;
	}

	/**
	 * Sets the signature creation time from the hashed section
	 * of the packet.
	 * <br>
	 * RFC 2440 5.2.3.4 ( 5.2.2 for V3 signatures )
	 * 
	 * @param definitive required the data to be signed
	 */
	public void setCreationTime(
		long creationTime,
		boolean definitive,
		boolean critical)
	{
		if (version != 4)
			this.creationTime = creationTime;
		else
		{
			addSubpacket(
				SignatureSubpacket.TYPE_SIGNATURE_CREATION_TIME,
				Conversions.longToBytes(creationTime, 4),
				definitive,
				critical);
		}
	}

	/**
	 * Indicates whether or not the certification performed by the
	 * signature is exportable.  Default is true.
	 * <br>
	 * RFC 2440 5.2.3.11
	 * 
	 * @param exportable false if certification should not be exported
	 * @param definitive sign the data
	 * @param critical must be recognized by recipient software
	 */
	public void setExportableCertification(
		boolean exportable,
		boolean definitive,
		boolean critical)
	{
		addSubpacket(
			SignatureSubpacket.TYPE_EXPORTABLE_CERTIFICATION,
			new byte[] {(byte) (exportable ? 1 : 0)},
			definitive,
			critical);
	}

	/**
	 * Sets the features supported by the user's implementation.
	 * <br>
	 * RFC 2440 5.2.3.24
	 *
	 * @param features the features
	 * @param definitive sign the data
	 * @param critical must be recognized by recipient software
	 */
	public void setFeatures(
		Features features,
		boolean definitive,
		boolean critical)
	{
		addSubpacket(
			SignatureSubpacket.TYPE_FEATURES,
			features.getBytes(),
			definitive,
			critical);
	}

	/**
	 * Sets the public key algorithm.
	 */
	public void setHashAlgorithm(int hashAlgorithm)
	{
		this.hashAlgorithm = hashAlgorithm;
		//this.hashAlgorithmIsOnDefault = false;
	}

	/**
	 * Sets the issuer key ID.
	 * <br>
	 * RFC 2440 5.2.3.5 ( 5.2.2 for V3 signatures )
	 * 
	 * @param definitive require the data to be signed
	 */
	public void setIssuerKeyID(
		byte[] issuerKeyID,
		boolean definitive,
		boolean critical)
	{
		if (version != 4)
			this.issuerKeyID = issuerKeyID;
		else
			addSubpacket(
				SignatureSubpacket.TYPE_ISSUER_KEY_ID,
				issuerKeyID,
				definitive,
				critical);

	}

	/**
	 * Sets the key expiration time from the packet.
	 * <br>
	 * RFC 2440 5.2.3.6
	 * 
	 * @param time in seconds since Jan. 1, 1970 00:00 UTC
	 * @param definitive sign the data
	 * @param critical must be recognized by recipient software
	 */
	public void setKeyExpirationTime(
		long time,
		boolean definitive,
		boolean critical)
	{
		addSubpacket(
			SignatureSubpacket.TYPE_KEY_EXPIRATION_TIME,
			Conversions.longToBytes(time, 4),
			definitive,
			critical);
	}

	/**
	 * Sets the key flags.
	 * <br>
	 * RFC 2440 5.2.3.21
	 *
	 * @param keyFlags the key flags
	 * @param definitive sign the data
	 * @param critical must be recognized by recipient software
	 */
	public void setKeyFlags(
		KeyFlags keyFlags,
		boolean definitive,
		boolean critical)
	{
		addSubpacket(
			SignatureSubpacket.TYPE_KEY_FLAGS,
			keyFlags.getBytes(),
			definitive,
			critical);
	}

	/**
	 * Sets the preferred key server.
	 * <br>
	 * RFC 2440 5.2.3.18
	 *
	 * @param url a url to the preferred key server
	 * @param definitive sign the data
	 * @param critical must be recognized by recipient software
	 */
	public void setKeyPreferredKeyServer(
		byte[] url,
		boolean definitive,
		boolean critical)
	{
		addSubpacket(
			SignatureSubpacket.TYPE_PREFERRED_KEY_SERVER,
			url,
			definitive,
			critical);
	}

	/**
	 * Sets the key server preferences.
	 * <br>
	 * RFC 2440 5.2.3.17
	 *
	 * @param keyServerPreferences the preferences
	 * @param definitive sign the data
	 * @param critical must be recognized by recipient software
	 */
	public void setKeyServerPreferences(
		KeyServerPreferences keyServerPreferences,
		boolean definitive,
		boolean critical)
	{
		addSubpacket(
			SignatureSubpacket.TYPE_KEY_SERVER_PREFERENCES,
			keyServerPreferences.getBytes(),
			definitive,
			critical);
	}

	/**
	 *  Sets the left sixteen bits of the hash.
	 */
	public void setLeftSixteenBitsOfHash(byte[] hashBytes)
	{
		this.leftSixteenBitsOfHash = hashBytes;
	}

	/**
	 * Adds notation data to the signature.
	 * <br>
	 * RFC 2440 5.2.3.16
	 *
	 * @param notationData the data to store
	 * @param definitive sign the data
	 * @param critical must be recognized by recipient software
	 */
	public void setNotationData(
		NotationData notationData,
		boolean definitive,
		boolean critical)
	{
		addSubpacket(
			SignatureSubpacket.TYPE_NOTATION_DATA,
			notationData.getBytes(),
			definitive,
			critical);
	}

	/**
	 * Sets the policy URL where the policy under which this signature
	 * was issued can be found.
	 * <br>
	 * RFC 2440 5.2.3.20
	 *
	 * @param url a url to the policy
	 * @param definitive sign the data
	 * @param critical must be recognized by recipient software
	 */
	public void setPolicyUrl(byte[] url, boolean definitive, boolean critical)
	{
		addSubpacket(
			SignatureSubpacket.TYPE_POLICY_URL,
			url,
			definitive,
			critical);
	}

	/**
	 * Sets the preferred compression algorithms.
	 * <br>
	 * RFC 2440 5.2.3.9
	 * 
	 * @param algorithms the algorithms in order where 0 is most preferable
	 * @param definitive sign the data
	 * @param critical must be recognized by recipient software
	 */
	public void setPreferredCompressionAlgorithms(
		byte[] algorithms,
		boolean definitive,
		boolean critical)
	{
		addSubpacket(
			SignatureSubpacket.TYPE_PREFERRED_COMPRESSION_ALGORITHMS,
			algorithms,
			definitive,
			critical);
	}

	/**
	 * Sets the preferred hash algorithms.
	 * <br>
	 * RFC 2440 5.2.3.8
	 * 
	 * @param algorithms the algorithms in order where 0 is most preferable
	 * @param definitive sign the data
	 * @param critical must be recognized by recipient software
	 */
	public void setPreferredHashAlgorithms(
		byte[] algorithms,
		boolean definitive,
		boolean critical)
	{
		addSubpacket(
			SignatureSubpacket.TYPE_PREFERRED_HASH_ALGORITHMS,
			algorithms,
			definitive,
			critical);
	}

	/**
	 * Sets the preferred symmetric algorithms.
	 * <br>
	 * RFC 2440 5.2.3.7
	 * 
	 * @param algorithms the algorithms in order where 0 is most preferable
	 * @param definitive sign the data
	 * @param critical must be recognized by recipient software
	 */
	public void setPreferredSymmetricAlgorithms(
		byte[] algorithms,
		boolean definitive,
		boolean critical)
	{
		addSubpacket(
			SignatureSubpacket.TYPE_PREFERRED_SYMMETRIC_ALGORITHMS,
			algorithms,
			definitive,
			critical);
	}

	/**
	 * Sets this signature on a user ID to specify the primary
	 * user ID for the key.
	 * <br>
	 * RFC 2440 5.2.3.19
	 * 
	 * @param isPrimaryUserID set to true if this is the primary user ID
	 * @param definitive sign the data
	 * @param critical must be recognized by recipient software
	 */
	public void setPrimaryUserID(
		boolean isPrimaryUserID,
		boolean definitive,
		boolean critical)
	{
		addSubpacket(
			SignatureSubpacket.TYPE_PRIMARY_USER_ID,
			new byte[] {(byte) (isPrimaryUserID ? 1 : 0)},
			definitive,
			critical);
	}

	/**
	 * Sets the public key algorithm.
	 */
	public void setPublicKeyAlgorithm(int publicKeyAlgorithm)
	{
		this.publicKeyAlgorithm = publicKeyAlgorithm;
	}

	/**
	 * Sets a regular expression restricting user ID's to which the
	 * trust signature applies.
	 * <br>
	 * RFC 2440 5.2.3.14
	 * 
	 * @param regularExpression the regular expression
	 * @param definitive sign the data
	 * @param critical must be recognized by recipient software
	 */
	public void setRegularExpression(
		byte[] regularExpression,
		boolean definitive,
		boolean critical)
	{
		addSubpacket(
			SignatureSubpacket.TYPE_REGULAR_EXPRESSION,
			regularExpression,
			definitive,
			critical);
	}

	/**
	 * Indicates whether or not the certification performed by the
	 * signature is revocable.  Default is true.
	 * <br>
	 * RFC 2440 5.2.3.12
	 * 
	 * @param revocable false if certification should not be revoked
	 * @param definitive sign the data
	 * @param critical must be recognized by recipient software
	 */
	public void setRevocable(
		boolean revocable,
		boolean definitive,
		boolean critical)
	{
		addSubpacket(
			SignatureSubpacket.TYPE_REVOCABLE,
			new byte[] {(byte) (revocable ? 1 : 0)},
			definitive,
			critical);
	}

	/**
	 * Specifies a key that is allowed to revoke this certification.
	 * <br>
	 * RFC 2440 5.2.3.15
	 * 
	 * @param revocationKey specifies the revocation key
	 * @param definitive sign the data
	 * @param critical must be recognized by recipient software
	 */
	public void setRevocationKey(
		RevocationKeySpecifier revocationKey,
		boolean definitive,
		boolean critical)
	{
		addSubpacket(
			SignatureSubpacket.TYPE_REVOCATION_KEY,
			revocationKey.getBytes(),
			definitive,
			critical);
	}

	/**
	 * Sets the reason for revocation for a revocation signature.
	 * <br>
	 * RFC 2440 5.2.3.23
	 *
	 * @param revocationReason the revocation reason information
	 * @param definitive sign the data
	 * @param critical must be recognized by recipient software
	 */
	public void setRevocationReason(
		RevocationReason revocationReason,
		boolean definitive,
		boolean critical)
	{
		addSubpacket(
			SignatureSubpacket.TYPE_REASON_FOR_REVOCATION,
			revocationReason.getBytes(),
			definitive,
			critical);
	}

	/**
	 * Sets the signature targeted by a revocation signature.
	 * <br>
	 * RFC 2440 5.2.3.25
	 *
	 * @param target the signature targeted by the revocation
	 * @param definitive sign the data
	 * @param critical must be recognized by recipient software
	 */
	public void setRevocationTarget(
		SignatureTarget target,
		boolean definitive,
		boolean critical)
	{
		addSubpacket(
			SignatureSubpacket.TYPE_SIGNATURE_TARGET,
			target.getBytes(),
			definitive,
			critical);
	}

	/**
	 * Sets the signature expiration time.
	 * <br>
	 * RFC 2440 5.2.3.10
	 * 
	 * @param expirationTime in seconds after signature creation
	 * @param definitive sign the data
	 * @param critical must be recognized by recipient software
	 */
	public void setSignatureExpirationTime(
		long expirationTime,
		boolean definitive,
		boolean critical)
	{
		addSubpacket(
			SignatureSubpacket.TYPE_SIGNATURE_EXPIRATION_TIME,
			Conversions.longToBytes(expirationTime, 4),
			definitive,
			critical);
	}

	/**
	 * Sets the MPI's that make up the actual signature.
	 */
	public void setSignatureMPIs(MPI[] mpis)
	{
		this.mpis = mpis;
	}

	/**
	 * Sets the signature type.
	 */
	public void setSignatureType(int signatureType)
	{
		this.signatureType = signatureType;
	}

	/**
	 * Indicates the level of trust the certification lends to the
	 * key that is signed.
	 * <br>
	 * RFC 2440 5.2.3.13
	 * 
	 * @param trustSignature the level of trust from 0 to 255
	 * @param definitive sign the data
	 * @param critical must be recognized by recipient software
	 */
	public void setTrustSignature(
		int trustSignature,
		boolean definitive,
		boolean critical)
	{
		addSubpacket(
			SignatureSubpacket.TYPE_TRUST_SIGNATURE,
			new byte[] {(byte) trustSignature },
			definitive,
			critical);
	}

	/**
	 * Sets the signer's user ID.
	 * <br>
	 * RFC 2440 5.2.3.22
	 *
	 * @param userID the signer's user ID
	 * @param definitive sign the data
	 * @param critical must be recognized by recipient software
	 */
	public void setUserID(byte[] userID, boolean definitive, boolean critical)
	{
		addSubpacket(
			SignatureSubpacket.TYPE_SIGNERS_USER_ID,
			userID,
			definitive,
			critical);
	}

	/**
	 * Sets the version, either 2, 3 or 4.
	 */
	public void setVersion(int version)
	{
		this.version = version;
	}

	/**
	 * Starts the signature creation procedure. <br>
	 * This will clear any existing issuer and creation time subpackets first.
	 * 
	 * @param secretKey
	 *            the key that will be used to generate the signature.
	 * @param signatureType
	 *            the type of signature to be generated.
	 * @param secretKey the key that will be used to generate the signature.
	 * @param signatureType the type of signature to be generated.
	 * @throws PgpException if the secret key has not been decrypted.
	 */
	public void startSigning(Key secretKey, int signatureType)
			throws UnrecoverableKeyException
	{
		startSigning(secretKey, signatureType, new Date().getTime() / 1000);
	}
	
	/**
	 * Starts the signature creation procedure. <br>
	 * This will clear any existing issuer and creation time subpackets first.
	 * 
	 * @param secretKey
	 *            the key that will be used to generate the signature.
	 * @param signatureType
	 *            the type of signature to be generated.
	 * @param secretKey the key that will be used to generate the signature.
	 * @param signatureType the type of signature to be generated.
	 * @param creationDate the time the signature is made.
	 * @throws PgpException if the secret key has not been decrypted.
	 */
	public void startSigning(Key secretKey, int signatureType, Date creationDate)
			throws UnrecoverableKeyException
	{
		startSigning(secretKey, signatureType, creationDate.getTime() / 1000);
	}
	
	/**
	 * Starts the signature creation procedure. <br>
	 * This will clear any existing issuer and creation time subpackets first.
	 * 
	 * @param secretKey
	 *            the key that will be used to generate the signature.
	 * @param signatureType
	 *            the type of signature to be generated.
	 * @param creationTime the time the signature is made in seconds since epoch
	 * @throws PgpException
	 *             if the secret key has not been decrypted.
	 */
	public void startSigning(
		Key secretKey,
		int signatureType,
		long creationTime)
		throws UnrecoverableKeyException
	{
		Logger.log(this, Logger.DEBUG, "Starting signature");
		if (status == STATUS_VERIFYING)
			throw new IllegalStateException("Already verifying a signature");
		if (status == STATUS_SIGNING)
			throw new IllegalStateException("Already creating a signature");
		if ( secretKey.getAlgorithm() == CIPHER_DSA )
		{
			// DSA always uses SHA1
			setHashAlgorithm(HASH_SHA1);
		}
		/*
		This is stopped here, cause we need to know the user ID to go futher.
		sbs - Nov 4, 2008
		else if ( hashAlgorithmIsOnDefault )
		{
			int prefHashAlgo = secretKey.getFirstSupportedHashAlgorithm();
			if ( prefHashAlgo != -1 ) setHashAlgorithm(prefHashAlgo);
		}
		*/
		for (int x = 0; x < hashedSubpackets.size(); x++)
		{
			SignatureSubpacket thisSubpacket =
				(SignatureSubpacket) hashedSubpackets.elementAt(x);
			if (thisSubpacket.getType()
				== SignatureSubpacket.TYPE_SIGNATURE_CREATION_TIME
				|| thisSubpacket.getType()
					== SignatureSubpacket.TYPE_ISSUER_KEY_ID)
			{
				while (hashedSubpackets.removeElement(thisSubpacket))
				{
				}
			}
		}
		for (int x = 0; x < unhashedSubpackets.size(); x++)
		{
			SignatureSubpacket thisSubpacket =
				(SignatureSubpacket) unhashedSubpackets.elementAt(x);
			if (thisSubpacket.getType()
				== SignatureSubpacket.TYPE_SIGNATURE_CREATION_TIME
				|| thisSubpacket.getType()
					== SignatureSubpacket.TYPE_ISSUER_KEY_ID)
			{
				while (unhashedSubpackets.removeElement(thisSubpacket))
				{
				}
			}
		}
		setCreationTime(creationTime, true, false);
		setPublicKeyAlgorithm(secretKey.getAlgorithm());
		setIssuerKeyID(secretKey.getKeyID(), false, false);
		setSignatureType(signatureType);
		status = STATUS_SIGNING;
		key = secretKey.getSecretKey();
		digest = AlgorithmFactory.getDigest(getHashAlgorithm());
	}

	/**
	 * Returns the size of the signature packet that would be required
	 * to store this signature.  Does not include the packet tag and length.
	 * (Starts with the signature version octet.)
	 * <br>
	 * Warning: If you call any  setter it will change this value.
	 * 
	 * @return the size of a signature packet
	 * that would hold this signature when a signature is completed.
	 */
	//TODO: delete this
	/*
	public int getPacketSize()
	{
		if (key == null)
			throw new IllegalStateException("Cannot determine packet size until signing is started");
		int length;
		if (getVersion() < 4)
		{
			length = 19;
		}
		else
		{
			length = 10;
	
			SignatureSubpacket[] hashedSubpackets = getHashedSubpackets();
			for (int x = 0; x < hashedSubpackets.length; x++)
				length += hashedSubpackets[x].getSubpacketSize();
	
			SignatureSubpacket[] unhashedSubpackets = getUnhashedSubpackets();
			for (int x = 0; x < unhashedSubpackets.length; x++)
				length += unhashedSubpackets[x].getSubpacketSize();
	
			// Creation time is mandatory, so if it hasn't been set,
			// add 6 bytes to accomodate it.
			if (getCreationTime(false) == -1)
				length += 6;
		}
		switch (getPublicKeyAlgorithm())
		{
			case theDsa :
				// TODO: Confirm that this always works.
				length
					+= new MPI(((DSAKeyParameters) key).getParameters().getQ())
						.getRaw()
						.length
					* 2;
				break;
				//TODO: RSA signatures.
			default :
				throw new RuntimeException("Not supported");
		}
		return length;
	}
	*/

	/**
	 * Starts the signature verification procedure.
	 */
	public void startVerification()
	{
		if (status == STATUS_VERIFYING)
			throw new IllegalStateException("Already verifying a signature");
		if (status == STATUS_SIGNING)
			throw new IllegalStateException("Already creating a signature");
		digest = AlgorithmFactory.getDigest(getHashAlgorithm());
		status = STATUS_VERIFYING;
	}

	public String toString()
	{
		return Conversions.byteArrayToString(getBytes(true, null), UTF8);
	}

	public String toString(Hashtable headers)
	{
		return Conversions.byteArrayToString(getBytes(true, headers), UTF8);
	}

	/**
	 * Updates the signature with the given data.
	 * 
	 * @param data the data for the update.
	 */
	public void update(byte[] data)
	{
		update(data, 0, data.length);
	}

	/**
	 * Updates the signature with the given data.
	 * 
	 * @param data the data for the update.
	 * @param offset the point in the array to start processing.
	 * @param len the len of the data to process.
	 */
	public void update(byte[] data, int offset, int len)
	{
		if (status == STATUS_NEUTRAL)
			throw new IllegalStateException("Must start verification or signing first");
		//if (getSignatureType() == theSignatureOnCanonicalTextDocument)
		//	throw new IllegalStateException("You must use update(String) to sign canonical text");
		digest.update(data, offset, len);
	}

	/**
	 * Updates the signature with the given data, converting it to
	 * bytes according to the character encoding set by 
	 * <code>setCharacterEncoding(String)</code>.
	 * <br>
	 * If you make multiple calls to this method, be sure that each
	 * string ends in a newline.
	 * 
	 * @param data the data for the update.
	 */
	public void update(String data)
	{
		try
		{
			if (status == STATUS_NEUTRAL)
				throw new IllegalStateException("Must start verification or signing first");
			byte[] rawBytes;
			if (getSignatureType() == SIGNATURE_ON_CANONICAL_TEXT)
			{
				BufferedReader lineReader =
					new BufferedReader(new StringReader(data));
				ByteArrayOutputStream bytesOut = new ByteArrayOutputStream();
				String thisCharacterEncoding;
				if ( characterEncoding != null )
					thisCharacterEncoding = Conversions.canonicalizeCharacterEncoding(characterEncoding);
				else
					thisCharacterEncoding = UTF8;
				OutputStreamWriter writer =
					new OutputStreamWriter(bytesOut, thisCharacterEncoding);
				String line;
				boolean onFirstLine = true;
				while ((line = lineReader.readLine()) != null)
				{
					if (onFirstLine)
						onFirstLine = false;
					else
					{
						writer.write('\r');
						writer.write('\n');
					}
					line = ("+" + line).trim().substring(1);
					writer.write(line, 0, line.length());
				}
				writer.flush();
				writer.close();
				rawBytes = bytesOut.toByteArray();
			}
			else
			{
				rawBytes =
					Conversions.stringToByteArray(data, characterEncoding);
			}
			digest.update(rawBytes, 0, rawBytes.length);
		}
		catch (IOException e)
		{
			e.printStackTrace();
			throw new RuntimeException(e.getMessage());
		}
	}

	public byte[] getBytesForSignature(int signatureVersion)
	{
		throw new RuntimeException("Not implemented");
	}
}