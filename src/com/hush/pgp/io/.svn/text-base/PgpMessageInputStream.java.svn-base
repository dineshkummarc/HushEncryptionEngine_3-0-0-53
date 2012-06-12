/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.pgp.io;

import java.io.IOException;
import java.io.InputStream;
import java.io.PushbackInputStream;
import java.math.BigInteger;
import java.util.Vector;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.ElGamalEngine;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import com.hush.pgp.AlgorithmFactory;
import com.hush.pgp.DataFormatException;
import com.hush.pgp.InvalidSignatureException;
import com.hush.pgp.Key;
import com.hush.pgp.Keyring;
import com.hush.pgp.MissingSelfSignatureException;
import com.hush.pgp.PgpConstants;
import com.hush.pgp.PgpUtils;
import com.hush.pgp.Signature;
import com.hush.pgp.cfb.WrongKeyException;
import com.hush.pgp.io.packets.CompressedDataInputStream;
import com.hush.pgp.io.packets.LiteralDataInputStream;
import com.hush.pgp.io.packets.OnePassSignatureInputStream;
import com.hush.pgp.io.packets.PacketInputStream;
import com.hush.pgp.io.packets.PublicKeyEncryptedSessionKeyInputStream;
import com.hush.pgp.io.packets.SignatureInputStream;
import com.hush.pgp.io.packets.SymmetricKeyEncryptedSessionKeyInputStream;
import com.hush.pgp.io.packets.SymmetricallyEncryptedDataInputStream;
import com.hush.pgp.io.packets.SymmetricallyEncryptedIntegrityProtectedDataInputStream;
import com.hush.util.ArrayTools;
import com.hush.util.Conversions;
import com.hush.util.Logger;
import com.hush.util.UnrecoverableKeyException;

/**
 * A stream to read in and decrypt a PGP encrypted and/or signed message.
 * <p>
 * There's a design issue with PGP symmetrically encrypted messages.
 * If there is more than symmetric key encrypted session key packet at
 * the beginning, there's no way to tell which one to use until you
 * actually start decrypting.
 * That's why this class gives the option of specifying which symmetric
 * key encrypted session key packet you wish to use.  If you don't
 * specify, it will use the last one, in conformance with the behavior
 * of GnuPG 1.2.1.
 * <p>
 * If applicable, an integrity check will be performed on close of the stream,
 * so be sure to close the stream after use.
 * <p>
 * If the cipher is 3DES, no compression is used, no partial packets are
 * used, and no MDC is used, this will decrypt 174661687 bytes in 32 seconds,
 * compared to 21 seconds for GnuPG.  This MDC slows it down substantially,
 * due to the buffer of the last 20 bytes that the integrity protected
 * stream keeps.
 * <p>
 * Use the <code>addPassword(byte[])</code>, <code>addSecretKey(com.hush.pgp.Key)</code>,
 * and <code>addKeyring(com.hush.pgp.KeyRing)</code> methods to add as many means of
 * decryption as desired.  The code will determine which to use.
 * <p>
 * This class automatically distinguishes between armored and unarmored messages.
 *
 * @author Brian Smith
 *
 */
public class PgpMessageInputStream extends InputStream
{
	private InputStream in = null;
	private InputStream symEncStream = null;
	private InputStream streamContainingLiteral = null;

	private LiteralDataInputStream literalStream = null;

	private Vector passwords = new Vector();
	private Vector secretKeys = new Vector();
	private Vector keyrings = new Vector();
	private Vector onePassSignatures = new Vector();
	private Vector signatures = new Vector();

	private boolean inited = false;

	private Vector sessionKeys = new Vector();
	private Vector algorithms = new Vector();

	private boolean closed = false;
	private boolean decryptOnly = false;

	/**
	 * @param in the underlying input stream.
	 */
	public PgpMessageInputStream(InputStream in)
	{
		this.in = new PushbackInputStream(in, 1);
	}

	/**
	 * @see java.io.InputStream#read()
	 */
	public int read() throws IOException
	{

		init();
		if (decryptOnly)
			return symEncStream.read();
		int b = literalStream.read();
		if (b != -1)
			updateSignatures(new byte[] {(byte) b }, 0, 1);
		return b;
	}

	/**
	 * @see java.io.InputStream#read(byte[])
	 */
	public int read(byte[] b) throws IOException
	{

		init();
		if (decryptOnly)
			return symEncStream.read(b);
		int x = literalStream.read(b);
		updateSignatures(b, 0, x);
		return x;
	}

	/**
	 * @see java.io.InputStream#read(byte[], int, int)
	 */
	public int read(byte[] b, int offset, int len) throws IOException
	{
		init();
		if (decryptOnly)
			return symEncStream.read(b, offset, len);
		int x = literalStream.read(b, offset, len);
		updateSignatures(b, offset, x);
		return x;
	}

	/**
	 * @see java.io.InputStream#close()
	 */
	public void close() throws IOException
	{
		init();

		if (!decryptOnly)
		{
			// Read to the end of the literal stream to be sure all signatures are
			// completely updated.
			byte[] b = new byte[512];
			int x;
			while ((x = literalStream.read(b)) != -1)
			{
				updateSignatures(b, 0, x);
			}

			// Read any signature packets that might exist to close off 
			// one pass signatures.
			PacketInputStream packet =
				new PacketInputStream(streamContainingLiteral);
			int onePassSignatureIndex = onePassSignatures.size() - 1;
			while (packet.getType() != -1)
			{
				switch (packet.getType())
				{
					case PgpConstants.PACKET_TAG_MODIFICATION_DETECTION_CODE :
						// If it's a modification detection code packet,
						// read right through.  It will automatically
						// be verified by the
						// SymmetricallyEncryptedIntegrityProtectectedDataInputStream
						if (symEncStream != streamContainingLiteral
							|| !(symEncStream
								instanceof SymmetricallyEncryptedIntegrityProtectedDataInputStream))
							throw new IOException("MDC packet without symmetrically encrypted integrity protected data packet");
						while (packet.read() != -1)
						{
						}
						break;
					case PgpConstants.PACKET_TAG_SIGNATURE :
						if (onePassSignatureIndex == -1)
						{
							Logger.log(
								this,
								Logger.ERROR,
								"Signature packet at end of message "
									+ "without associated one pass signature packet at beginning");
							while (packet.read() != -1)
							{
							}
						}
						else
						{
							Signature thisSig =
								(Signature) onePassSignatures.elementAt(
									onePassSignatureIndex--);
							byte[] originalKeyID =
								thisSig.getIssuerKeyID(false);
							new SignatureInputStream(packet, thisSig).close();
							if (!ArrayTools
								.equals(
									originalKeyID,
									thisSig.getIssuerKeyID(false)))
							{
								Logger.log(
									this,
									Logger.ERROR,
									"Signature packet key ID does not match"
										+ " corresponding one pass signature packet key ID");
								Logger.hexlog(
									this,
									Logger.ERROR,
									"One pass signature packet key ID:",
									originalKeyID);
								Logger.hexlog(
									this,
									Logger.ERROR,
									"Signature packet key ID:",
									thisSig.getIssuerKeyID(false));
							}
						}
						break;
					default :
						Logger.log(
							this,
							Logger.WARNING,
							"Unexpected packet of type: " + packet.getType());
						while (packet.read() != -1)
						{
						}
				}
				packet = new PacketInputStream(streamContainingLiteral);
			}

		}

		// Read to the end of the stream to ensure that integrity checks are performed.
		if (symEncStream != null)
		{
			while (symEncStream.read() != -1)
			{
			}
			symEncStream.close();
		}

		in.close();
		in = null;
		symEncStream = null;
		streamContainingLiteral = null;
		literalStream = null;
		passwords = null;
		secretKeys = null;
		keyrings = null;

		// wipe all the session keys
		for (int x = 0; x < sessionKeys.size(); x++)
		{
			ArrayTools.wipe((byte[]) sessionKeys.elementAt(x));
		}
		sessionKeys = null;

		closed = true;
	}

	/**
	 * Adds a password that will be used when attempting to decrypt
	 * the message.
	 * 
	 * @param password the password.
	 */
	public void addPassword(byte[] password)
	{
		passwords.addElement(password);
	}

	/**
	 * Adds a secret key that will be used when attempting to decrypt
	 * the message.
	 * 
	 * Keys will only be tried if they match the key ID specified in a public key
	 * encrypted session key packet read from the stream, or if that packet specifies
	 * a wildcard key ID.
	 * 
	 * @param secretKey the key to be used for decryption.
	 * @throws PgpException if the secret key has not been decrypted.
	 */
	public void addSecretKey(Key secretKey) throws UnrecoverableKeyException
	{
		// If the secret key has not been decrypted, this will
		// throw an exception.
		secretKey.getSecretKey();
		secretKeys.addElement(secretKey.getEncryptionKey());
		Logger.hexlog(
			this,
			Logger.DEBUG,
			"Added secret key: ",
			secretKey.getKeyID());
	}
	
	/**
	 * Adds a key ring that will be searched for keys that can
	 * be used to decrypt the message.
	 * 
	 * Keys will only be tried if they match the key ID specified in a public key
	 * encrypted session key packet read from the stream, or if that packet specifies
	 * a wildcard key ID.
	 * 
	 * @param keyring the key to be used for decryption
	 * @throws PgpException if the secret key has not been decrypted
	 */
	public void addKeyring(Keyring keyring)
	{
		keyrings.addElement(keyring);
	}

	/**
	 * Gets any signatures on the stream.  Don't call this until you close the
	 * stream.
	 * 
	 * @return signatures all the signatures from the message.
	 */
	public Signature[] getSignatures()
	{
		Vector allSigs = new Vector();
		for (int x = 0; x < onePassSignatures.size(); x++)
		{
			allSigs.addElement(onePassSignatures.elementAt(x));
		}
		for (int x = 0; x < signatures.size(); x++)
		{
			allSigs.addElement(signatures.elementAt(x));
		}
		Signature[] signatureArray = new Signature[allSigs.size()];
		allSigs.copyInto(signatureArray);
		return signatureArray;
	}

	/**
	 * Use this to read directly from the symmetrically encrypted data stream.
	 * without attempting to decode the packets
	 * contained within.
	 *
	 */
	public void decryptOnly()
	{
		if (inited)
			throw new IllegalStateException("Stream already initialized");
		this.decryptOnly = true;
	}

	/**
	 * Returns the character encoding specified in the armor, if this stream
	 * was armored.  If the stream is not armored, UTF-8 is assumed.
	 * 
	 * @throws IOException
	 */
	public String getCharacterEncoding() throws IOException
	{
		init();
		if (in instanceof ArmorInputStream)
			return ((ArmorInputStream) in).getCharacterEncoding();
		return PgpConstants.UTF8;
	}

	private void init()
		throws
			IOException,
			DataFormatException,
			WrongKeyException,
			NoSessionKeyException
	{
		if (inited)
			return;

		if (closed)
			throw new IllegalStateException("Stream closed");

		PushbackInputStream pushBack = ((PushbackInputStream) in);
		int firstChar = pushBack.read();
		pushBack.unread(firstChar);
		pushBack = null;

		if (firstChar == (int) '-')
		{
			in = new ArmorInputStream(in);
			if (((ArmorInputStream) in).getType()
				!= PgpConstants.ARMOR_TYPE_PGP_MESSAGE
				&& ((ArmorInputStream) in).getType()
					!= PgpConstants.ARMOR_TYPE_PGP_SIGNED_MESSAGE)
				throw new DataFormatException("Wrong PGP armor type");
		}

		PacketInputStream packet = null;

		boolean inMessage = false;
		while (!inMessage)
		{
			packet = new PacketInputStream(in);
			switch (packet.getType())
			{
				case PgpConstants
					.PACKET_TAG_SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY :
					handleSymmetricallyEncryptedSessionKeyPacket(packet);
					break;
				case PgpConstants.PACKET_TAG_PUBLIC_KEY_ENCRYPTED_SESSION_KEY :
					handlePublicKeyEncryptedSessionKeyPacket(packet);
					break;
				case PgpConstants.PACKET_TAG_SYMMETRICALLY_ENCRYPTED_DATA :
					if (getSessionKeyArray().length == 0)
						throw new NoSessionKeyException("Unable to decrypt the session key. Are you sure this message was encrypted to you?");

					symEncStream =
						new SymmetricallyEncryptedDataInputStream(
							packet,
							getAlgorithmArray(),
							getSessionKeyArray());
					packet = new PacketInputStream(symEncStream);
					inMessage = true;
					break;
				case PgpConstants
					.PACKET_TAG_SYMMETRICALLY_ENCRYPTED_INTEGRITY_PROTECTED_DATA :
					if (getSessionKeyArray().length == 0)
						throw new NoSessionKeyException("Unable to decrypt the session key. Are you sure this message was encrypted to you?");
					symEncStream =
						new SymmetricallyEncryptedIntegrityProtectedDataInputStream(
							packet,
							getAlgorithmArray(),
							getSessionKeyArray());
					packet = new PacketInputStream(symEncStream);
					inMessage = true;
					break;
				case PgpConstants.PACKET_TAG_MARKER :
					// Doesn't mean anything
					while (packet.read() != -1)
					{
					}
					break;
				case PgpConstants.PACKET_TAG_ONE_PASS_SIGNATURE :
				case PgpConstants.PACKET_TAG_SIGNATURE :
				case PgpConstants.PACKET_TAG_COMPRESSED_DATA :
				case PgpConstants.PACKET_TAG_LITERAL_DATA :
					// Skip to next step
					inMessage = true;
					break;
				case -1 :
					throw new DataFormatException("Unexpected end of message");
				default :
					// Unknown packet type.
					Logger.log(
						this,
						Logger.WARNING,
						"Unrecognized packet type: " + packet.getType());
					while (packet.read() != -1)
					{
					}
			}
		}

		if (decryptOnly)
		{
			inited = true;
			return;
		}

		if (packet.getType() == PgpConstants.PACKET_TAG_COMPRESSED_DATA)
		{
			streamContainingLiteral = new CompressedDataInputStream(packet);
			packet = new PacketInputStream(streamContainingLiteral);

		}
		else if (symEncStream != null)
		{
			streamContainingLiteral = symEncStream;
		}
		else
		{
			streamContainingLiteral = in;
		}

		boolean foundLiteral = false;

		while (!foundLiteral)
		{
			switch (packet.getType())
			{
				case PgpConstants.PACKET_TAG_LITERAL_DATA :
					if (foundLiteral)
						throw new DataFormatException("Already found literal packet, but here's another one");
					literalStream = new LiteralDataInputStream(packet);
					foundLiteral = true;
					break;
				case PgpConstants.PACKET_TAG_ONE_PASS_SIGNATURE :
					OnePassSignatureInputStream onePassSigStream =
						new OnePassSignatureInputStream(packet);
					Signature onePassSignature =
						onePassSigStream.getSignature();
					onePassSignature.startVerification();
					onePassSignatures.addElement(onePassSignature);
					break;
				case PgpConstants.PACKET_TAG_SIGNATURE :
					SignatureInputStream sigStream =
						new SignatureInputStream(packet);
					Signature signature = sigStream.getSignature();
					signature.startVerification();
					signatures.addElement(signature);
					break;
				default :
					throw new DataFormatException(
						"Unsupported packet type in decrypted data: "
							+ packet.getType());
			}
			packet = new PacketInputStream(streamContainingLiteral);
		}
		inited = true;
	}

	private void handleSymmetricallyEncryptedSessionKeyPacket(PacketInputStream packet)
		throws DataFormatException, IOException
	{
		SymmetricKeyEncryptedSessionKeyInputStream symEncSessionKeyStream =
			new SymmetricKeyEncryptedSessionKeyInputStream(packet);
		byte[] encryptedSessionKey =
			symEncSessionKeyStream.getEncryptedSessionKey();

		int thisAlgorithm = -1;

		if (encryptedSessionKey == null)
		{

			// The password is the session key
			for (int x = 0; x < passwords.size(); x++)
			{
				thisAlgorithm = symEncSessionKeyStream.getAlgorithm();
				sessionKeys.addElement(
					symEncSessionKeyStream.getS2kAlgorithm().s2k(
						(byte[]) passwords.elementAt(x),
						PgpConstants
							.SYMMETRIC_CIPHER_KEY_LENGTHS[symEncSessionKeyStream
							.getAlgorithm()]));
				algorithms.addElement(new Integer(thisAlgorithm));
			}
		}
		else
		{
			for (int x = 0; x < passwords.size(); x++)
			{
				// The password encrypts a session key, which encrypts the
				// message
				byte[] keyToSessionKey =
					symEncSessionKeyStream.getS2kAlgorithm().s2k(
						(byte[]) passwords.elementAt(x),
						PgpConstants
							.SYMMETRIC_CIPHER_KEY_LENGTHS[symEncSessionKeyStream
							.getAlgorithm()]);
				BufferedBlockCipher passphraseCipher =
					AlgorithmFactory.getStandardCFBBlockCipher(
						symEncSessionKeyStream.getAlgorithm());
				passphraseCipher.init(
					false,
					new ParametersWithIV(
						new KeyParameter(keyToSessionKey),
						new byte[passphraseCipher.getBlockSize()]));

				byte[] decryptedSessionKeyBuffer =
					new byte[symEncSessionKeyStream
						.getEncryptedSessionKey()
						.length];

				Logger.log(
					this,
					Logger.DEBUG,
					"Encrypted session key length: "
						+ decryptedSessionKeyBuffer.length);

				int encryptedCount =
					passphraseCipher.processBytes(
						symEncSessionKeyStream.getEncryptedSessionKey(),
						0,
						decryptedSessionKeyBuffer.length,
						decryptedSessionKeyBuffer,
						0);
				try
				{
					passphraseCipher.doFinal(
						decryptedSessionKeyBuffer,
						encryptedCount);
				}
				catch (InvalidCipherTextException e)
				{
					throw DataFormatException.wrap(
							"Invalid cipher text during decryption", e);
				}

				try
				{

					// The first byte of the decrypted material indicates
					// the algorithm used to encrypt the message
					thisAlgorithm = decryptedSessionKeyBuffer[0];
					// Make sure we got a valid algorithm
					AlgorithmFactory.getPGPCFBBlockCipher(thisAlgorithm);

					

					// The remainder is the actual session key
					byte[] sessionKey =
						new byte[decryptedSessionKeyBuffer.length - 1];
					System.arraycopy(
						decryptedSessionKeyBuffer,
						1,
						sessionKey,
						0,
						sessionKey.length);

					sessionKeys.addElement(sessionKey);
					algorithms.addElement(new Integer(thisAlgorithm));

				}
				catch (IllegalArgumentException e)
				{
					Logger.log(
						this,
						Logger.WARNING,
						"This algorithm is not valid, probably because of a bad password decryption: "
							+ thisAlgorithm);
				}

			}
		}
	}

	private void handlePublicKeyEncryptedSessionKeyPacket(PacketInputStream packet)
		throws DataFormatException, IOException
	{

		PublicKeyEncryptedSessionKeyInputStream pubEncSessionKeyStream =
			new PublicKeyEncryptedSessionKeyInputStream(packet);
		BigInteger[] encryptedSessionKey =
			pubEncSessionKeyStream.getEncryptedSessionKey();
		boolean wildcard =
			ArrayTools.equals(
				pubEncSessionKeyStream.getKeyID(),
				PgpConstants.WILD_CARD_KEY_ID);

		Logger.hexlog(
			this,
			Logger.DEBUG,
			"Key ID in packet: ",
			pubEncSessionKeyStream.getKeyID());

		// The session key will be protected by a secret key.

		// First try any secret keys that were specified.
		for (int x = 0; x < secretKeys.size(); x++)
		{
			Key thisKey = (Key) secretKeys.elementAt(x);
			if (wildcard
				|| ArrayTools.equals(
					pubEncSessionKeyStream.getKeyID(),
					thisKey.getKeyID()))
			{
				if (publicKeyDecryptSessionKey(encryptedSessionKey, thisKey, wildcard))
				{
					return;
				}
				// Make a last ditch effort if a main key was specified
				// and there are decryption subkeys
				Key[] otherDecryptionKeys = thisKey.getAllEncryptionKeys();
				for ( int y=0; y < otherDecryptionKeys.length; y++ )
				{
					if ( otherDecryptionKeys[y] != thisKey 
							&& publicKeyDecryptSessionKey(encryptedSessionKey,
									otherDecryptionKeys[y], wildcard))
					{
						return;
					}
				}
			}
		}

		// If we haven't found a key by now, look for a key in any key rings
		// that were specified.
		for (int x = 0; x < keyrings.size(); x++)
		{
			Keyring thisKeyring = (Keyring) keyrings.elementAt(x);
			if ( thisKeyring == null ) continue;
			try
			{
				if (wildcard)
				{
					Key[] keysFromKeyring = thisKeyring.getAllEncryptionKeys();
					for (int y = 0; y < keysFromKeyring.length; y++)
					{
						if (publicKeyDecryptSessionKey(encryptedSessionKey,
							keysFromKeyring[y], wildcard))
						{
							return;
						}
					}
				}
				else
				{
					Key thisKey =
						thisKeyring.getKey(pubEncSessionKeyStream.getKeyID());
					if (thisKey != null)
					{
						if (publicKeyDecryptSessionKey(encryptedSessionKey,
							thisKey, wildcard))
						{
							return;
						}
					}
				}

			}
			catch (InvalidSignatureException e)
			{
				Logger.logThrowable(
					this,
					Logger.ERROR,
					"Secret key error", e);
			}
			catch (MissingSelfSignatureException e)
			{
				Logger.logThrowable(
					this,
					Logger.ERROR,
					"Secret key error", e);
			}
		}
	}

	/**
	 * Returns true if the operation is successful, indicating to the
	 * calling code that it is okay to stop trying keys.
	 * 
	 * @param suppressWarnings use with wildcard user ID to reduce output
	 */
	private boolean publicKeyDecryptSessionKey(
		BigInteger[] encryptedSessionKey,
		Key thisKey, boolean suppressWarnings)
	{

		try
		{
			Logger.hexlog(
				this,
				Logger.DEBUG,
				"Attempting to decrypt session key with: ",
				thisKey.getKeyID());
			int thisAlgorithm;
			PKCS1Encoding cipher;
			byte[] cipherText;
			switch (thisKey.getAlgorithm())
			{
				case PgpConstants.CIPHER_ELGAMAL :
				case PgpConstants.CIPHER_ELGAMAL_ENCRYPT_ONLY :
					byte[] int1 =
						Conversions.bigIntegerToUnsignedBytes(
							encryptedSessionKey[0]);
					Logger.log(
						this,
						Logger.DEBUG,
						"ElGamal int 1 size: " + int1.length);
					byte[] int2 =
						Conversions.bigIntegerToUnsignedBytes(
							encryptedSessionKey[1]);
					Logger.log(
						this,
						Logger.DEBUG,
						"ElGamal int 2 size: " + int2.length);
					int largerIntSize =
						int1.length > int2.length ? int1.length : int2.length;
					cipherText = new byte[largerIntSize * 2];
					System.arraycopy(
						int1,
						0,
						cipherText,
						largerIntSize - int1.length,
						int1.length);
					System.arraycopy(
						int2,
						0,
						cipherText,
						cipherText.length - int2.length,
						int2.length);

					/*
					cipherText = new byte[int1.length + int2.length];
					System.arraycopy(int1, 0, cipherText, 0, int1.length);
					System.arraycopy(int2, 0, cipherText, int1.length, int2.length);
					*/

					cipher = new PKCS1Encoding(new ElGamalEngine());
					break;
				case PgpConstants.CIPHER_RSA :
				case PgpConstants.CIPHER_RSA_ENCRYPT_ONLY :
					cipherText =
						Conversions.bigIntegerToUnsignedBytes(
							encryptedSessionKey[0]);
					cipher = new PKCS1Encoding(new RSAEngine());
					break;
				default :
					throw new DataFormatException(
						"Unsupported public key algorithm: "
							+ thisKey.getAlgorithm());
			}
			Logger.hexlog(
				this,
				Logger.DEBUG,
				"Raw input to cipher: ",
				cipherText);
			cipher.init(false, thisKey.getSecretKey());
			byte[] decryptedBytes =
				cipher.processBlock(cipherText, 0, cipherText.length);
			thisAlgorithm = decryptedBytes[0];
			byte[] sessionKey = new byte[decryptedBytes.length - 3];
			byte[] checksum = new byte[2];
			System.arraycopy(
				decryptedBytes,
				1,
				sessionKey,
				0,
				sessionKey.length);
			System.arraycopy(
				decryptedBytes,
				1 + sessionKey.length,
				checksum,
				0,
				2);
			if (ArrayTools
				.equals(checksum, PgpUtils.checksumMod65536(sessionKey)))
			{
				sessionKeys.addElement(sessionKey);
				algorithms.addElement(new Integer(thisAlgorithm));
				Logger.log(
					this,
					Logger.DEBUG,
					"Symmetric algorithm: " + thisAlgorithm);
				return true;
			}
			else
			{
				if ( ! suppressWarnings )
				Logger.hexlog(
					this,
					Logger.WARNING,
					"Failed to decrypt session key packet with this key: ",
					thisKey.getKeyID());
			}
		}
		catch (UnrecoverableKeyException e)
		{
			Logger.logThrowable(
				this,
				Logger.ERROR,
				"Could not get secret key; you probably forgot to decrypt your key before adding it", e);
		}
		catch (InvalidCipherTextException e)
		{
			if ( ! suppressWarnings ) Logger.logThrowable(
					this,
					Logger.WARNING,
					"Warning", e);
		}
		catch (Exception e)
		{
			if ( ! suppressWarnings ) Logger.logThrowable(
					this,
					Logger.WARNING,
					"Warning", e);
		}
		return false;
	}

	private byte[][] getSessionKeyArray()
	{
		byte[][] sessionKeyArray = new byte[sessionKeys.size()][];
		sessionKeys.copyInto(sessionKeyArray);
		return sessionKeyArray;
	}

	private int[] getAlgorithmArray()
	{
		int[] algorithmArray = new int[algorithms.size()];
		for(int x=0; x<algorithms.size();x++)
		{
			algorithmArray[x] = ((Integer)algorithms.elementAt(x)).intValue();
		}
		return algorithmArray;
	}
	
	private void updateSignatures(byte[] b, int offset, int length)
	{
		for (int x = 0; x < onePassSignatures.size(); x++)
		{
			((Signature) onePassSignatures.elementAt(x)).update(
				b,
				offset,
				length);
		}
	}
}