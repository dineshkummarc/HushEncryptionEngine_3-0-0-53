/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.pgp;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.PushbackInputStream;
import java.io.Serializable;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import com.hush.pgp.io.ArmorInputStream;
import com.hush.pgp.io.ArmorOutputStream;
import com.hush.pgp.io.packets.PacketInputStream;
import com.hush.pgp.io.packets.PacketOutputStream;
import com.hush.pgp.io.packets.PublicKeyInputStream;
import com.hush.pgp.io.packets.PublicKeyOutputStream;
import com.hush.pgp.io.packets.PublicSubkeyInputStream;
import com.hush.pgp.io.packets.PublicSubkeyOutputStream;
import com.hush.pgp.io.packets.SecretKeyInputStream;
import com.hush.pgp.io.packets.SecretKeyOutputStream;
import com.hush.pgp.io.packets.SecretSubkeyInputStream;
import com.hush.pgp.io.packets.SecretSubkeyOutputStream;
import com.hush.pgp.io.packets.SignatureInputStream;
import com.hush.pgp.io.packets.SignatureOutputStream;
import com.hush.pgp.io.packets.TrustInputStream;
import com.hush.pgp.io.packets.UserAttributeInputStream;
import com.hush.pgp.io.packets.UserIDInputStream;
import com.hush.pgp.io.packets.UserIDOutputStream;
import com.hush.util.ArrayTools;
import com.hush.util.Conversions;
import com.hush.util.ExceptionWrapper;
import com.hush.util.Logger;
import com.hush.util.UnrecoverableKeyException;

/**
 * An object representing a PGP key ring, with the implementation
 * to either read or write it's contents from or to a stream.
 *
 * @author Brian Smith
 *
 */
public class Keyring implements Serializable, Cloneable
{
	private static final long serialVersionUID = 1641562278823180631L;
	private Hashtable keys = new Hashtable();
	private Vector standaloneSignatures = new Vector();
	transient private Key currentMainKey;
	transient private Key currentSubKey;
	transient private Signable currentUserIDOrAttribute;
	transient private Signature currentCertificationSignature;
	private boolean verifySelfSignatures = true;
	
	public static Keyring loadKeyring(InputStream in)
			throws DataFormatException, IOException
	{
		Keyring keyring = new Keyring();
		keyring.load(in);
		return keyring;
	}

	public static Keyring loadKeyring(String in) throws DataFormatException,
			IOException
	{
		return loadKeyring(Conversions.stringToByteArray(in, PgpConstants.UTF8));
	}

	public static Keyring loadKeyring(byte[] in) throws DataFormatException,
			IOException
	{
		return loadKeyring(new ByteArrayInputStream(in));
	}
	
	public static Keyring createKeyring(Key[] keys)
	{
		Keyring keyring = new Keyring();
		for(int i=0; i<keys.length; i++)
		{
			keyring.addKey(keys[i]);
		}
		return keyring;
	}
	
	public static Keyring createKeyring(Key key)
	{
		Keyring keyring = new Keyring();
		keyring.addKey(key);
		return keyring;
	}
	
	/**
	 * Reads in a key ring from a stream. Bad or unknown packets will be 
	 * skipped.
	 * <p>
	 * It should be possible to call this several times to incrementally
	 * load keys.
	 * 
	 * @param in the stream from which to read the key ring
	 */
	public void load(InputStream in) throws DataFormatException, IOException
	{
		int currentPacketType;
		PacketInputStream currentPacket;

		PushbackInputStream pushBack = new PushbackInputStream(in);
		int firstChar = pushBack.read();
		pushBack.unread(firstChar);

		InputStream armoredOrNot;

		if (firstChar == (int) '-')
		{
			armoredOrNot = new ArmorInputStream(in);
		}
		else
			armoredOrNot = pushBack;

		while (true)
		{
			currentPacket = new PacketInputStream(armoredOrNot);
			if ((currentPacketType = currentPacket.getType()) == -1)
			{
				// If it's an armored input stream, see if another armored
				// stream follows
				if (armoredOrNot instanceof ArmorInputStream)
				{
					armoredOrNot.close();
					armoredOrNot = new ArmorInputStream(in);
					currentPacket = new PacketInputStream(armoredOrNot);
					try
					{
						if ((currentPacketType = currentPacket.getType())
							== -1)
						{
							return;
						}
					}
					catch (DataFormatException e)
					{
						return;
					}
				}
				else
					return;
			}
			try
			{
				switch (currentPacketType)
				{
					case PgpConstants.PACKET_TAG_PUBLIC_KEY :
						readKey(currentPacket, false, false);
						break;
					case PgpConstants.PACKET_TAG_PUBLIC_SUBKEY :
						readKey(currentPacket, false, true);
						break;
					case PgpConstants.PACKET_TAG_SECRET_KEY :
						readKey(currentPacket, true, false);
						break;
					case PgpConstants.PACKET_TAG_SECRET_SUBKEY :
						readKey(currentPacket, true, true);
						break;
					case PgpConstants.PACKET_TAG_SIGNATURE :
						readSignature(currentPacket);
						break;
					case PgpConstants.PACKET_TAG_USER_ID :
						readUserID(currentPacket);
						break;
					case PgpConstants.PACKET_TAG_USER_ATTRIBUTE :
						readUserAttribute(currentPacket);
						break;
					case PgpConstants.PACKET_TAG_TRUST :
						readTrustInfo(currentPacket);
						break;
					default :
						// First packet is neither a public nor a private key packet, skip.
						throw new DataFormatException(
							"Unrecognized or unexpected packet type: "
								+ currentPacketType);
				}
			}
			catch (IOException e)
			{
				Logger.logThrowable(
					this,
					Logger.WARNING,
					"Error handling packet of type: " + currentPacketType, e);
				while (currentPacket.read() != -1)
				{
					;
				}
			}
		}

	}
	/**
	 * Saves in a key ring to a stream.
	 * 
	 * @param out the stream to which to write the key ring
	 * @param armor set to true to ASCII armor the output
	 * @param secret export secret parts, and only keys that have secret parts
	 */
	public void save(OutputStream out, boolean armor, boolean secret)
	{
		try
		{
			Enumeration e = keys.elements();
			OutputStream armoredOrNot;
			if (armor)
			{
				armoredOrNot =
					new ArmorOutputStream(
						out,
						(secret)
							? PgpConstants.ARMOR_TYPE_PGP_PRIVATE_KEY
							: PgpConstants.ARMOR_TYPE_PGP_PUBLIC_KEY);
			}
			else
			{
				armoredOrNot = out;
			}
			while (e.hasMoreElements())
			{
				writeKey((Key) e.nextElement(), armoredOrNot, false, secret);
			}

			if (armoredOrNot != out)
				armoredOrNot.close();
		}
		catch (IOException e)
		{
			// We don't expect that this will happen, since we're reading
			// data that is already loaded.
			throw ExceptionWrapper.wrapInRuntimeException("Should never happen", e);
		}
	}

	private void writeKey(
		Key key,
		OutputStream out,
		boolean isSubkey,
		boolean secret)
		throws IOException
	{
		if (secret)
		{
			if (key.getSecretKeyMaterial() == null)
			{
				// There is no secret component to this key.
				// Abort.
				return;
			}
			if (isSubkey)
				new SecretSubkeyOutputStream(
					new PacketOutputStream(out, true),
					key)
					.close();
			else
				new SecretKeyOutputStream(
					new PacketOutputStream(out, true),
					key)
					.close();
		}
		else
		{
			if (isSubkey)
				new PublicSubkeyOutputStream(
					new PacketOutputStream(out, true),
					key)
					.close();
			else
				new PublicKeyOutputStream(
					new PacketOutputStream(out, true),
					key)
					.close();
		}
		int x;
		UserID[] userIDs = key.getUserIDs();
		for (x = 0; x < userIDs.length; x++)
		{
			new UserIDOutputStream(
				new PacketOutputStream(out, true),
				userIDs[x])
				.close();
			Signature[] sigsOnUserID = userIDs[x].getSignatures(-1, null);
			int y;
			for (y = 0; y < sigsOnUserID.length; y++)
			{
				new SignatureOutputStream(
					new PacketOutputStream(out, true),
					sigsOnUserID[y])
					.close();
			}
		}
		Signature[] sigsOnKey = key.getSignatures(-1, null);
		for (x = 0; x < sigsOnKey.length; x++)
		{
			new SignatureOutputStream(
				new PacketOutputStream(out, true),
				sigsOnKey[x])
				.close();
		}
		Key[] subkeys = key.getSubkeys();
		for (x = 0; x < subkeys.length; x++)
			writeKey(subkeys[x], out, true, secret);
	}

	private void readKey(
		PacketInputStream currentPacket,
		boolean secret,
		boolean subkey)
		throws IOException
	{
		PublicKeyInputStream keyInputStream;
		if (secret)
		{
			if (subkey)
				keyInputStream = new SecretSubkeyInputStream(currentPacket);
			else
				keyInputStream = new SecretKeyInputStream(currentPacket);
		}
		else
		{
			if (subkey)
				keyInputStream = new PublicSubkeyInputStream(currentPacket);
			else
				keyInputStream = new PublicKeyInputStream(currentPacket);
		}
		Key key = keyInputStream.getKey();
		if (subkey)
		{
			if (keys.size() == 0)
				throw new IOException("Secret subkey without secret key");
			//Key mainKey = (Key) keys.elementAt(keys.size() - 1);
			currentSubKey = currentMainKey.addSubkey(key);
		}
		else
		{
			// This will add the key and set the current main
			// key to this key, unless a key with that key ID
			// already existed, in which case they will be merged
			// and the currentMainKey will be the key into which
			// this key was merged.
			currentMainKey = addKey(key);
		}
	}

	private void readSignature(PacketInputStream currentPacket)
		throws IOException
	{
		SignatureInputStream sigIn = new SignatureInputStream(currentPacket);
		
		// Check to make sure the signature is an appropriate type
		// for it's target.
		switch (sigIn.getSignature().getSignatureType())
		{
			case Signature.SIGNATURE_STANDALONE :
				standaloneSignatures.addElement(sigIn.getSignature());
				return;
			case Signature.SIGNATURE_CERTIFICATION_GENERIC :
			case Signature.SIGNATURE_CERTIFICATION_PERSONA :
			case Signature.SIGNATURE_CERTIFICATION_CASUAL :
			case Signature.SIGNATURE_CERTIFICATION_POSITIVE :
				if ( currentUserIDOrAttribute == null )
				{
					Logger.log(
						this,
						Logger.WARNING,
						"Found a certification signature that cannot "
							+ "be associated with a user ID or attribute");
					return;
				}
				currentCertificationSignature = sigIn.getSignature();
				currentUserIDOrAttribute.addSignature(sigIn.getSignature());
				return;
			case Signature.SIGNATURE_CERTIFICATION_REVOCATION :
				if ( currentCertificationSignature == null )
				{
					Logger.log(
						this,
						Logger.ERROR,
						"Found a certification revocation signature that "
							+ "be associated with a certification signature");
					return;
				}
				currentCertificationSignature.addSignature(sigIn.getSignature());
				return;
			case Signature.SIGNATURE_SUBKEY_BINDING :
				if ( currentSubKey == null )
				{
					Logger.log(
						this,
						Logger.WARNING,
						"Found a subkey binding signature that cannot "
							+ "be associated with a subkey");
					return;
				}
				currentSubKey.addSignature(sigIn.getSignature());
				return;
			case Signature.SIGNATURE_SUBKEY_REVOCATION :
				if ( currentSubKey == null )
				{
					Logger.log(
						this,
						Logger.WARNING,
						"Found a subkey revocation signature that cannot "
							+ "be associated with a subkey");
					return;
				}
				currentSubKey.addSignature(sigIn.getSignature());
				return;
			case Signature.SIGNATURE_DIRECTLY_ON_KEY :
				if ( currentMainKey == null )
				{
					Logger.log(
						this,
						Logger.WARNING,
						"Found a signature directly on a key that cannot "
							+ "be associated with a main key");
					return;
				}
				currentMainKey.addSignature(sigIn.getSignature());
				return;
			case Signature.SIGNATURE_KEY_REVOCATION :
				if ( currentMainKey == null )
				{
					Logger.log(
						this,
						Logger.ERROR,
						"Found a key revocation signature that cannot "
							+ "be associated with a main key");
					return;
				}
				currentMainKey.addSignature(sigIn.getSignature());
				return;
			default :
				Logger.log(
					this,
					Logger.WARNING,
					"Unexpected signature type: "
						+ sigIn.getSignature().getSignatureType());
				return;
		}
	}

	private void readUserID(PacketInputStream currentPacket)
		throws DataFormatException, IOException
	{
		if ( currentMainKey == null )
		{
			Logger.log(this, Logger.WARNING, "Found user ID before main key, discarding");
			return;
		}
		UserIDInputStream userIDIn = new UserIDInputStream(currentPacket);
		UserID userID = userIDIn.getUserID();
		currentUserIDOrAttribute = currentMainKey.addUserID(userID);
	}

	private void readUserAttribute(PacketInputStream currentPacket)
		throws DataFormatException, IOException
	{
		if ( currentMainKey == null )
		{
			Logger.log(this, Logger.WARNING, "Found user attribute before main key, discarding");
			return;
		}
		UserAttributeInputStream userAttributeIn =
			new UserAttributeInputStream(currentPacket);
		UserAttribute userAttribute = userAttributeIn.getUserAttribute();
		currentMainKey.addUserAttribute(userAttribute);
		currentUserIDOrAttribute = userAttribute;
	}

	private void readTrustInfo(PacketInputStream currentPacket)
		throws DataFormatException, IOException
	{
		if ( currentMainKey == null )
		{
			Logger.log(this, Logger.WARNING, "Found trust info before main key, discarding");
			return;
		}
		TrustInputStream trustIn = new TrustInputStream(currentPacket);
		ByteArrayOutputStream trustInfo = new ByteArrayOutputStream();
		byte[] buffer = new byte[512];
		int x;
		while ((x = trustIn.read(buffer)) != -1)
		{
			trustInfo.write(buffer, 0, x);
		}
		currentMainKey.addTrustInformation(trustInfo.toByteArray());
	}

	/**
	 * Returns all the keys which possess the specified user ID.
	 *
	 * @param userID the user ID to search for.
	 * @return an array of secret keys.
	 */
	public Key[] getKeys(String userID)
		throws InvalidSignatureException, MissingSelfSignatureException
	{
		Vector v = new Vector();
		Enumeration e;
		e = keys.elements();
		Key key;
		while (e.hasMoreElements())
		{
			key = (Key) e.nextElement();
			if (userID == null || key.hasUserID(userID))
			{
				if (getVerifySelfSignatures())
					key.verifySelfSignatures();
				v.addElement(key);
			}
		}
		Key[] keys = new Key[v.size()];
		v.copyInto(keys);
		return keys;
	}

	/**
	 * Returns the key for the specified keyID.
	 *
	 * @param keyID the key ID of the key to retrieve.
	 * @return an array of secret keys.
	 * @throws InvalidSignatureException if a signature on a key failed
	 * @throws MissingSelfSignature if a key is missing a self signature
	 */
	public Key getKey(byte[] keyID)
		throws InvalidSignatureException, MissingSelfSignatureException
	{
		Enumeration e;
		e = keys.elements();
		Key key;
		while (e.hasMoreElements())
		{
			key = (Key) e.nextElement();
			byte[] thisKeyID = key.getKeyID();
			if (ArrayTools
				.equals(
					thisKeyID,
					thisKeyID.length - 4,
					keyID,
					keyID.length - 4,
					4))
			{
				if (getVerifySelfSignatures())
					key.verifySelfSignatures();
				return key;
			}
			Key[] subkeys = key.getSubkeys();
			for (int x = 0; x < subkeys.length; x++)
			{
				thisKeyID = subkeys[x].getKeyID();
				if (ArrayTools
					.equals(
						thisKeyID,
						thisKeyID.length - 4,
						keyID,
						keyID.length - 4,
						4))
				{
					if (getVerifySelfSignatures())
						subkeys[x].verifySelfSignatures();
					return subkeys[x];
				}
			}
		}
		return null;
	}

	/**
	 * Returns every encryption key (or subkey) in the keyring as
	 * a flat array.  Useful for trying to decrypt wildcard messages
	 * that could be encrypted with any key.
	 */
	public Key[] getAllEncryptionKeys() throws InvalidSignatureException, MissingSelfSignatureException
	{
		Vector encryptionKeys = new Vector();
		Key keys[] = getKeys(null);
		for ( int x=0; x<keys.length; x++)
		{
			Key theseEncKeys[] = keys[x].getAllEncryptionKeys();
			for ( int y=0; y<theseEncKeys.length; y++)
			{
				encryptionKeys.addElement(theseEncKeys[y]);
			}
		}
		Key ret[] = new Key[encryptionKeys.size()];
		encryptionKeys.copyInto(ret);
		return ret;
	}
	
	/**
	 * Adds the key to the keyring.  If a key with the Key ID
	 * already exists, merge it into the original and return
	 * a reference to the original.
	 * 
	 * @param key the key to add
	 * @return a reference to the added (or merged) key
	 */
	public Key addKey(Key key)
	{
		String keyID = Conversions.bytesToHexString(key.getKeyID());
		Object existingKeyObject = keys.get(keyID);
		if (existingKeyObject == null)
		{
			// There's no existing key with that key ID.  Just add the
			// new key.
			keys.put(Conversions.bytesToHexString(key.getKeyID()), key);
			return key;
		}

		// A key with that key ID already exists.  Attempt to merge the
		// information.
		Key existingKey = ((Key) existingKeyObject);
		existingKey.merge(key);
		return existingKey;
	}

	/**
	 * Returns whether this class is set to verify self-signatures on
	 * key retrieval.
	 * 
	 * @return true if self-signatures will be verified; false if not.
	 */
	public boolean getVerifySelfSignatures()
	{
		return verifySelfSignatures;
	}

	/**
	 * Sets the whether self-signatures are verified on key retrieval.
	 * Don't set this to false unless you know what you are doing.
	 * 
	 * @param verifySelfSignatures whether or not to verify self-signatures.
	 */
	public void setVerifySelfSignatures(boolean verifySelfSignatures)
	{
		this.verifySelfSignatures = verifySelfSignatures;
	}

	/**
	 * Gets the entire key ring as an ASCII armored string.
	 * Exports only public components of keys.
	 */
	public String toString()
	{
		return toString(false);
	}

	/**
	 * Gets the entire key ring as an ASCII armored string.
	 * 
	 * @param secret export the secret parts, and only keys that have secret parts
	 */
	public String toString(boolean secret)
	{
		ByteArrayOutputStream b = new ByteArrayOutputStream();
		save(b, true, secret);
		return Conversions.byteArrayToString(
			b.toByteArray(),
			PgpConstants.UTF8);
	}

	public void printInformation(OutputStream out)
	{
		PrintStream writer = new PrintStream(out);
		Enumeration e = keys.elements();
		while (e.hasMoreElements())
		{
			Key key = (Key) e.nextElement();
			writer.print("Main key: ");
			writer.println(Conversions.bytesToHexString(key.getKeyID()));
			printSignatures(key, writer, "  ");
			UserID[] userIDs = key.getUserIDs();
			for (int x = 0; x < userIDs.length; x++)
			{
				writer.print("  User ID: ");
				writer.println(userIDs[x].toString());
				printSignatures(userIDs[x], writer, "    ");
			}
			Key[] subkeys = key.getSubkeys();
			for (int x = 0; x < subkeys.length; x++)
			{
				writer.print("  Sub key: ");
				writer.println(
					Conversions.bytesToHexString(subkeys[x].getKeyID()));
				printSignatures(subkeys[x], writer, "    ");
			}
		}
	}

	private void printSignatures(
		Signable signable,
		PrintStream writer,
		String offset)
	{
		Signature[] sigs = signable.getSignatures(-1, null);
		for (int x = 0; x < sigs.length; x++)
		{
			writer.print(offset);
			writer.print("Signature type: ");
			writer.println(sigs[x].getSignatureType());
			writer.print(offset);
			writer.print("Signer: ");
			writer.println(
				Conversions.bytesToHexString(sigs[x].getIssuerKeyID(false)));
		}
	}
	
	public void decryptSecretKeys(byte[] passphrase) throws InvalidSignatureException, MissingSelfSignatureException, UnrecoverableKeyException, DataFormatException
	{
		Key keys[] = getKeys(null);
		for( int x=0; x<keys.length; x++)
		{
			keys[x].decryptSecretKey(passphrase);
		}
	}
	
	public void encryptSecretKeys(
			byte[] passphrase,
			int symmetricAlgorithm,
			int s2kType,
			int s2kHashAlgorithm,
			int s2kCount)
			throws UnrecoverableKeyException, InvalidSignatureException, MissingSelfSignatureException
	{
		Key keys[] = getKeys(null);
		for( int x=0; x<keys.length; x++)
		{
			keys[x].encryptSecretKeyMaterial(passphrase,
					symmetricAlgorithm,
					s2kType,
					s2kHashAlgorithm,
					s2kCount, false);
		}	
	}
}