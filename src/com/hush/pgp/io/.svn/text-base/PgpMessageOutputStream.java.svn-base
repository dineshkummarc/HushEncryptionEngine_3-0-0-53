/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.pgp.io;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;
import java.util.zip.Deflater;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.ElGamalEngine;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import com.hush.pgp.AlgorithmFactory;
import com.hush.pgp.InvalidSignatureException;
import com.hush.pgp.Key;
import com.hush.pgp.Keyring;
import com.hush.pgp.MPI;
import com.hush.pgp.MissingSelfSignatureException;
import com.hush.pgp.PgpConstants;
import com.hush.pgp.PgpUtils;
import com.hush.pgp.S2kAlgorithm;
import com.hush.pgp.Signature;
import com.hush.pgp.io.packets.CompressedDataOutputStream;
import com.hush.pgp.io.packets.LiteralDataOutputStream;
import com.hush.pgp.io.packets.OnePassSignatureOutputStream;
import com.hush.pgp.io.packets.PacketOutputStream;
import com.hush.pgp.io.packets.PublicKeyEncryptedSessionKeyOutputStream;
import com.hush.pgp.io.packets.SignatureOutputStream;
import com.hush.pgp.io.packets.SymmetricKeyEncryptedSessionKeyOutputStream;
import com.hush.pgp.io.packets.SymmetricallyEncryptedDataOutputStream;
import com
	.hush
	.pgp
	.io
	.packets
	.SymmetricallyEncryptedIntegrityProtectedDataOutputStream;
import com.hush.util.ArrayTools;
import com.hush.util.ExceptionWrapper;
import com.hush.util.Logger;
import com.hush.util.UnrecoverableKeyException;

/**
 * A <code>PgpMessageOutputStream</code> creates a PGP message as
 * described in RFC 2440 10.2.
 */
public class PgpMessageOutputStream
	extends OutputStream
	implements PgpConstants
{
	private boolean plaintext = false;

	private boolean useArmor = false;

	private OutputStream originalOut;
	
	private OutputStream out;

	private int symmetricKeyEncryptionAlgorithm = CIPHER_3DES;

	private int compressionAlgorithm = COMPRESSION_ALGORITHM_ZIP;

	// default to what's set in signature
	private int signatureHashAlgorithm = -1;
	
	private SecureRandom random;

	private Vector recipients = new Vector();
	private Vector recipientUserIDs = new Vector();
	private Vector recipientWildcardKeyIDs = new Vector();

	private Vector symmetricKeysThatEncryptTheSessionKey = new Vector();
	private Vector s2ksThatEncryptTheSessionKey = new Vector();
	private Vector symmetricKeyAlgorithmsThatEncryptTheSessionKey = new Vector();

	private boolean text = false;
	private byte[] filename = null;
	private long timestamp = System.currentTimeMillis() / 1000;
	private long length = -1;
	// 0 is determine from algorithm, 1 is yes, 2 is no
	private int mdc = 0;
	private int compressionLevel = Deflater.BEST_COMPRESSION;
	private boolean noLiteral = false;

	private ArmorOutputStream armoredOut;
	private OutputStream encryptedOut;
	private OutputStream compressedOut;
	private OutputStream literalOut;

	// This will be out, encryptedOut, or compressedOut	
	private OutputStream streamContainingLiteral;

	private Signature[] onePassSignatures = new Signature[0];
	private boolean inited = false;

	private Hashtable headers = new Hashtable();

	/**
	 * Creates a <code>PgpMessageOutputStream</code> and saves the arguments
	 * for later use.
	 * 
	 * @param out the underlying output stream
	 * @param random a source of random data for encryption operations
	 */
	public PgpMessageOutputStream(OutputStream out, SecureRandom random)
	{
		this.originalOut = out;
		this.out = out;
		this.random = random;
	}

	/**
	 * @see java.io.OutputStream#write(int)
	 */
	public void write(int b) throws IOException
	{
		init();
		for (int x = 0; x < onePassSignatures.length; x++)
			onePassSignatures[x].update(new byte[] {(byte) b });
		literalOut.write(b);
	}

	/**
	 * @see java.io.OutputStream#write(byte[])
	 */
	public void write(byte[] b) throws IOException
	{
		init();
		for (int x = 0; x < onePassSignatures.length; x++)
			onePassSignatures[x].update(b);
		literalOut.write(b);
	}

	/**
	 * @see java.io.OutputStream#write(byte[], int, int)
	 */
	public void write(byte[] b, int off, int len) throws IOException
	{
		init();
		for (int x = 0; x < onePassSignatures.length; x++)
			onePassSignatures[x].update(b, off, len);
		literalOut.write(b, off, len);
	}

	/**
	 * Closes the stream.  Does not close the underlying stream.
	 * 
	 * @see java.io.OutputStream#close()
	 */
	public void close() throws IOException
	{

		init();

		literalOut.close();
		literalOut = null;

		for (int x = onePassSignatures.length - 1; x >= 0; x--)
		{
			onePassSignatures[x].finishSigning(random);
			SignatureOutputStream sig =
				new SignatureOutputStream(
					new PacketOutputStream(streamContainingLiteral),
					onePassSignatures[x]);
			sig.close();
		}
		//onePassSignatures = null;

		if (!noLiteral && compressedOut != null)
		{
			compressedOut.flush();
			compressedOut.close();
		}

		encryptedOut.flush();
		// Close encryptedOut, unless it is the wrapped stream
		if ( encryptedOut != originalOut )
		{
			encryptedOut.close();
		}

		if (armoredOut != null && armoredOut != encryptedOut)
		{
			armoredOut.flush();
			armoredOut.close();
		}

		compressedOut = null;
		encryptedOut = null;
		out = null;
		originalOut = null;
	}

	/**
	 * Adds a one-pass signer to the message. This means that the signature
	 * is created as data is written to the stream. This method must be called
	 * before any data is written to the stream.
	 * 
	 * @param signer the signer of the message.
	 */
	public void addOnePassSigner(Key signer)
		throws UnrecoverableKeyException
	{
		if (inited)
			throw new IllegalStateException("Cannot add a signature after writing has begun");
		if (noLiteral)
			throw new IllegalStateException("Cannot add a signature if noLiteral is set");
		Signature[] tmpSignatures = new Signature[onePassSignatures.length + 1];
		int x = 0;
		for (x = 0; x < onePassSignatures.length; x++)
		{
			tmpSignatures[x] = onePassSignatures[x];
		}
		tmpSignatures[x] = new Signature();
		if ( signatureHashAlgorithm != -1 )
			tmpSignatures[x].setHashAlgorithm(signatureHashAlgorithm);
		tmpSignatures[x].startSigning(
			signer,
			Signature.SIGNATURE_ON_BINARY_DOCUMENT,
			System.currentTimeMillis() / 1000);
		onePassSignatures = tmpSignatures;
	}

	/**
	 * Adds a public key to which the message will be encrypted.  This method
	 * must be called before any data is written to the stream.
	 * <p>
	 * If the key is a main key, the first encryption key or subkey
	 * wil be used.
	 * <p>
	 * Algorithms to be used will be chosen based on what is acceptable
	 * to all user IDs attached to the key.
	 * 
	 * @param recipient the key to which the message will be encrypted
	 */
	public void addRecipient(Key recipient)
	{
		addRecipient(recipient, null, false);
	}

	public void addRecipient(Keyring recipient)
			throws InvalidSignatureException, MissingSelfSignatureException
	{
		Key[] keys = recipient.getKeys(null);
		for (int i = 0; i < keys.length; i++)
		{
			addRecipient(keys[i]);
		}
	}
	
	/**
	 * Adds a public key to which the message will be encrypted.  This method
	 * must be called before any data is written to the stream.
	 * 
	 * If the key is a main key, the first encryption key or subkey
	 * will be used.
	 * 
	 * @param recipient the key to which the message will be encrypted.
	 * @param userID choose preferred algorithms based on this userID;
	 *   if null, choose algorithms acceptable to any user ID
	 * @param useWildcardKeyID if true, the key ID for the recipient
	 * will not be specified, making the message more anonymous
	 */
	public void addRecipient(
		Key recipient,
		String userID,
		boolean useWildcardKeyID)
	{
		if (inited)
			throw new IllegalStateException("Cannot add a recipient after writing has begun");
		Key encryptionKey;
		if (recipient.getMainKey() == recipient)
			encryptionKey = recipient.getEncryptionKey();
		else
			encryptionKey = recipient;
		if (encryptionKey == null)
			throw new IllegalArgumentException("The main key is not an encryption key and there was no valid, non-revoked sub key");
		recipients.addElement(encryptionKey);
		recipientUserIDs.addElement(userID);
		recipientWildcardKeyIDs.addElement(new Boolean(useWildcardKeyID));
	}

	/**
	 * If the plaintext flag is set to true, the message can be sent without
	 * any passwords or recipients. This prevents a message from accidentally
	 * being broadcasted unencrypted.
	 *
	 * @param plaintext set to true to create a plaintext message.
	 */
	public void setPlaintext(boolean plaintext)
	{
		this.plaintext = plaintext;
	}

	/**
	 * 
	 */
	public void addPassword(
		byte[] password,
		int s2kType,
		int hashAlgorithm,
		int iterationCount)
	{
		// Create the salt to be used for s2k
		byte[] salt = new byte[8];
		random.nextBytes(salt);
		S2kAlgorithm s2k =
			new S2kAlgorithm(s2kType, hashAlgorithm, salt, iterationCount);
		s2ksThatEncryptTheSessionKey.addElement(s2k);
		symmetricKeysThatEncryptTheSessionKey.addElement(
			s2k.s2k(
				password,
				SYMMETRIC_CIPHER_KEY_LENGTHS[symmetricKeyEncryptionAlgorithm]));
		symmetricKeyAlgorithmsThatEncryptTheSessionKey.addElement(new Integer(symmetricKeyEncryptionAlgorithm));
	}

	public void addPassword(byte[] password)
	{
		addPassword(
			password,
			S2kAlgorithm.S2K_TYPE_ITERATED_AND_SALTED,
			HASH_SHA1,
			DEFAULT_S2K_ITERATION_COUNT);
	}

	public Signature[] getOnePassSignatures()
	{
		return onePassSignatures;
	}

	private void init() throws IOException
	{

		if (out == null)
			throw new IOException("Stream is closed");

		if (inited)
			return;

		if (useArmor)
		{
			armoredOut = new ArmorOutputStream(out, ARMOR_TYPE_PGP_MESSAGE);
			armoredOut.setHeaders(headers);
			this.out = armoredOut;
		}

		if (recipients.size() == 0 && symmetricKeysThatEncryptTheSessionKey.size() == 0 && !plaintext)
		{
			throw new IllegalStateException(
				"Must set plaintext flag before"
					+ " sending a plaintext message");
		}

		if (recipients.size() > 0)
		{

			byte[][] symPrefs = new byte[recipients.size()][];
			byte[][] compPrefs = new byte[recipients.size()][];

			for (int x = 0; x < recipients.size(); x++)
			{
				Key mainKey = ((Key) recipients.elementAt(x)).getMainKey();

				symPrefs[x] =
					mainKey.getPreferredSymmetricKeyAlgorithms(
						(String) recipientUserIDs.elementAt(x));

				compPrefs[x] =
					mainKey.getPreferredCompressionAlgorithms(
						(String) recipientUserIDs.elementAt(x));
			}

			byte[] symprefsIntersection = ArrayTools.intersection(symPrefs);

			if (symprefsIntersection.length > 0)
				symmetricKeyEncryptionAlgorithm = symprefsIntersection[0];

			byte[] compprefsIntersection = ArrayTools.intersection(compPrefs);

			if (compprefsIntersection.length > 0)
				compressionAlgorithm = compprefsIntersection[0];
		}

		byte[] sessionKey = null;
		// Create the key to be used for the message
		if (symmetricKeysThatEncryptTheSessionKey.size() != 0 || recipients.size() != 0)
		{
			sessionKey =
				new byte[SYMMETRIC_CIPHER_KEY_LENGTHS[symmetricKeyEncryptionAlgorithm]];

			random.nextBytes(sessionKey);
		}

		for (int x = 0; x < recipients.size(); x++)
		{
			Key recipient = (Key) recipients.elementAt(x);

			// Encrypt the sessionKey
			byte[] inputForSessionKeyEncryption =
				new byte[sessionKey.length + 3];
			inputForSessionKeyEncryption[0] = (byte) symmetricKeyEncryptionAlgorithm;

			System.arraycopy(
				sessionKey,
				0,
				inputForSessionKeyEncryption,
				1,
				sessionKey.length);

			PgpUtils.checksumMod65536(
				inputForSessionKeyEncryption,
				1,
				sessionKey.length,
				inputForSessionKeyEncryption,
				1 + sessionKey.length);

			Logger.hexlog(
				this,
				Logger.DEBUG,
				"Input to PKCS1: ",
				inputForSessionKeyEncryption);
			MPI[] encryptedSessionKey;
			switch (recipient.getAlgorithm())
			{
				case CIPHER_ELGAMAL :
				case CIPHER_ELGAMAL_ENCRYPT_ONLY :
					PKCS1Encoding cipher =
						new PKCS1Encoding(new ElGamalEngine());
					cipher.init(true, recipient.getPublicKey());
					try
					{
						encryptedSessionKey = new MPI[2];
						byte[] encryptedSessionKeyRaw =
							cipher.processBlock(
								inputForSessionKeyEncryption,
								0,
								inputForSessionKeyEncryption.length);
						Logger.hexlog(
							this,
							Logger.DEBUG,
							"Raw output from cipher: ",
							encryptedSessionKeyRaw);
						byte[] encryptedSessionKeyRaw1 =
							new byte[encryptedSessionKeyRaw.length / 2];
						byte[] encryptedSessionKeyRaw2 =
							new byte[encryptedSessionKeyRaw.length / 2];
						System.arraycopy(
							encryptedSessionKeyRaw,
							0,
							encryptedSessionKeyRaw1,
							0,
							encryptedSessionKeyRaw1.length);
						System.arraycopy(
							encryptedSessionKeyRaw,
							encryptedSessionKeyRaw1.length,
							encryptedSessionKeyRaw2,
							0,
							encryptedSessionKeyRaw2.length);
						BigInteger gamma =
							new BigInteger(1, encryptedSessionKeyRaw1);
						encryptedSessionKey[0] = new MPI(gamma);
						BigInteger phi =
							new BigInteger(1, encryptedSessionKeyRaw2);
						encryptedSessionKey[1] = new MPI(phi);
					}
					catch (InvalidCipherTextException e)
					{
						throw new RuntimeException("Caught InvalidCipherTextException. This should never happen.");
					}
					break;
				case CIPHER_RSA :
				case CIPHER_RSA_ENCRYPT_ONLY :
					PKCS1Encoding rsaCipher =
						new PKCS1Encoding(new RSAEngine());
					rsaCipher.init(true, recipient.getPublicKey());
					try
					{
						byte[] encryptedSessionKeyRaw =
							rsaCipher.processBlock(
								inputForSessionKeyEncryption,
								0,
								inputForSessionKeyEncryption.length);

						encryptedSessionKey = new MPI[1];
						encryptedSessionKey[0] =
							new MPI(new BigInteger(encryptedSessionKeyRaw));
					}
					catch (InvalidCipherTextException e)
					{
						throw new RuntimeException("Caught InvalidCipherTextException. This should never happen.");
					}
					break;
				default :
					throw new IOException(
						"Unsupported algorithm: " + recipient.getAlgorithm());
			}
			ArrayTools.wipe(inputForSessionKeyEncryption);
			// Create the public-key encrypted session key packet.
			new PublicKeyEncryptedSessionKeyOutputStream(
				new PacketOutputStream(out),
				recipient.getAlgorithm(),
				recipientWildcardKeyIDs.elementAt(x).equals(Boolean.TRUE)
					? WILD_CARD_KEY_ID
					: recipient.getKeyID(),
				MPI.mpis2Bytes(encryptedSessionKey))
				.close();
		}

		// Note, in this section of the code, be careful to maintain the
		// distinction between the algorithms that encrypt the session keys
		// (stored in symmetricKeyAlgorithmsThatEncryptTheSessionKey) and
		// the algorithm that will encrypt the actual message.  They may not
		// be the same, as the message encryption algorithm will be either
		// the most popular symmetric algorithm in the recipient preferences
		// or the current default (stored in symmetricKeyEncryptionAlgorithm)
		// whereas the keys that have already been generated off passwords
		// added with addPassword would not have known that ahead of time, so
		// they just use whatever the current default was at that time.
		// -sbs
		Enumeration symKeyEnum = symmetricKeysThatEncryptTheSessionKey.elements();
		Enumeration s2kEnum = s2ksThatEncryptTheSessionKey.elements();
		Enumeration symKeyAlgoEnum = symmetricKeyAlgorithmsThatEncryptTheSessionKey.elements();
		while (symKeyEnum.hasMoreElements())
		{
			byte[] thisSymKey = (byte[]) symKeyEnum.nextElement();
			S2kAlgorithm thisS2k = (S2kAlgorithm) s2kEnum.nextElement();
			int thisSymKeyAlgo = ((Integer)symKeyAlgoEnum.nextElement()).intValue();
			
			byte[] encryptedSessionKey = new byte[sessionKey.length + 1];
			encryptedSessionKey[0] = (byte) symmetricKeyEncryptionAlgorithm;
			System.arraycopy(
				sessionKey,
				0,
				encryptedSessionKey,
				1,
				sessionKey.length);
			BufferedBlockCipher passphraseCipher =
				AlgorithmFactory.getStandardCFBBlockCipher(
					thisSymKeyAlgo);
			passphraseCipher.init(
				true,
				new ParametersWithIV(
					new KeyParameter(thisSymKey),
					new byte[passphraseCipher.getBlockSize()]));
			int encryptedCount =
				passphraseCipher.processBytes(
					encryptedSessionKey,
					0,
					encryptedSessionKey.length,
					encryptedSessionKey,
					0);
			try
			{
				passphraseCipher.doFinal(
					encryptedSessionKey,
					encryptedCount);
			}
			catch (InvalidCipherTextException e)
			{
				throw ExceptionWrapper
						.wrapInRuntimeException(
								"Got InvalidCipherTextException that should never happen",
								e);
			}
			// Create the symmetric-key encrypted session key packet.
			new SymmetricKeyEncryptedSessionKeyOutputStream(
				new PacketOutputStream(out),
				thisSymKeyAlgo,
				thisS2k,
				encryptedSessionKey)
				.close();

		}
		
		// Now we create a stream to write the actual plain text to.
		if (plaintext)
		{
			encryptedOut = out;
		}
		else if (
			mdc == 1
				|| (mdc == 0
					&& (symmetricKeyEncryptionAlgorithm == CIPHER_AES128
						|| symmetricKeyEncryptionAlgorithm == CIPHER_AES192
						|| symmetricKeyEncryptionAlgorithm == CIPHER_AES256
						|| symmetricKeyEncryptionAlgorithm == CIPHER_TWOFISH)))
		{
			encryptedOut =
				new SymmetricallyEncryptedIntegrityProtectedDataOutputStream(
					new PacketOutputStream(out),
					symmetricKeyEncryptionAlgorithm,
					sessionKey);
		}
		else
		{
			encryptedOut =
				new SymmetricallyEncryptedDataOutputStream(
					new PacketOutputStream(out),
					symmetricKeyEncryptionAlgorithm,
					sessionKey);
		}
		recipients = null;

		if (compressionLevel > 0)
		{
			compressedOut =
				new CompressedDataOutputStream(
					new PacketOutputStream(encryptedOut),
					compressionAlgorithm,
					compressionLevel);
			streamContainingLiteral = compressedOut;
		}
		else
			streamContainingLiteral = encryptedOut;

		if (noLiteral)
		{
			literalOut = streamContainingLiteral;
			inited = true;
			return;
		}

		OnePassSignatureOutputStream opSigs[] =
			new OnePassSignatureOutputStream[onePassSignatures.length];

		for (int x = 0; x < onePassSignatures.length; x++)
		{
			opSigs[x] =
				new OnePassSignatureOutputStream(
					new PacketOutputStream(streamContainingLiteral),
					onePassSignatures[x],
					onePassSignatures.length > 1);
			opSigs[x].close();
		}

		PacketOutputStream literalPacketOut =
			new PacketOutputStream(streamContainingLiteral);

		literalOut =
			new LiteralDataOutputStream(
				literalPacketOut,
				text,
				filename,
				timestamp,
				length);

		// Clear references to variables that are no longer needed.
		random = null;
		filename = null;
		inited = true;
	}

	/**
	 * Sets a header to place in the armor if the stream is armored.
	 * 
	 * @param key
	 * @param value
	 */
	public void setHeader(String key, String value)
	{
		if (inited)
			throw new IllegalStateException("Already inited");
		if (!useArmor)
			throw new IllegalStateException("Not an armored stream");
		headers.put(key, value);
	}

	/**
	 * Sets the headers to place in the armor if the stream is armored.
	 * This will override any headers that have already been set.
	 * 
	 * @param headers
	 */
	public void setHeaders(Hashtable headers)
	{
		if (inited)
			throw new IllegalStateException("Already inited");
		if (!useArmor)
			throw new IllegalStateException("Not an armored stream");
		this.headers = headers;
	}

	/**
	 * Sets the compression algorithm to use.  This will be overridden by if any
	 * recipients have been added, and so is relevant only for password encrypted messages.
	 * 
	 * @param compressionAlgorithm the compression algorithm
	 */
	public void setCompressionAlgorithm(int compressionAlgorithm)
	{
		this.compressionAlgorithm = compressionAlgorithm;
	}

	/**
	 * Sets the compression level for zip and zlib compression.
	 * 
	 * @param compressionLevel the compression level
	 */
	public void setCompressionLevel(int compressionLevel)
	{
		this.compressionLevel = compressionLevel;
	}

	/**
	 * Sets the filename to use in the literal data packet.
	 * 
	 * @param filename the filename to use
	 */
	public void setFilename(byte[] filename)
	{
		this.filename = filename;
	}

	/**
	 * If the length of the data to be written is known, use this method to set it
	 * and avoid using partial length packets.  Will result in shorter output.
	 * 
	 * @param length the length of the data to be written
	 */
	public void setLength(long length)
	{
		this.length = length;
	}

	/**
	 * Set to true to use modification detection.  Defaults to false.
	 * 
	 * @param useMdc set to true to use modification detection
	 */
	public void setUseMdc(boolean useMdc)
	{
		mdc = useMdc ? 1 : 2;
	}

	/**
	 * Sets the symmetric encryption algorithm to use.  This will be overridden by if any
	 * recipients with preferred symmetric ciphers have been added, and so is relevant only
	 * for password encrypted messages.
	 * 
	 */
	public void setSymmetricCipher(int i)
	{
		symmetricKeyEncryptionAlgorithm = i;
	}

	/**
	 * Set to true to write the data directly to the compression and encryption
	 * streams without wrapping it in a literal data packet.
	 * This is false by default.
	 * 
	 * @param noLiteral 
	 */
	public void setNoLiteral(boolean noLiteral)
	{
		this.noLiteral = noLiteral;
	}

	/**
	 * Set to true if you want there to be a flag in the literal data packet indicating
	 * that the data is text.  This defaults to false
	 * 
	 * @param isText the data is text
	 */
	public void setText(boolean isText)
	{
		text = isText;
	}

	/**
	 * Set to true if you want to ASCII armor the message.
	 * 
	 * Defaults to false.
	 * 
	 * @param useArmor true to use ASCII armor
	 */
	public void setUseArmor(boolean useArmor)
	{
		this.useArmor = useArmor;
	}

	/**
	 * Sets the timestamp of the message in seconds since 1970-01-01 00:00:00 UTC.
	 * 
	 * @param timestamp the timestamp
	 */
	public void setTimestamp(long timestamp)
	{
		this.timestamp = timestamp;
	}

	public void setSignatureHashAlgorithm(int signatureHashAlgorithm)
	{
		this.signatureHashAlgorithm = signatureHashAlgorithm;
	}

}