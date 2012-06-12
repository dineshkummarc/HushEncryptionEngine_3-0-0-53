/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.hee;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import com.hush.hee.keyserver.Keyserver;
import com.hush.hee.keyserver.PrivateKey;
import com.hush.hee.keyserver.PrivateKeyInformation;
import com.hush.hee.keyserver.PublicKey;
import com.hush.hee.keyserver.PublicKeyInformation;
import com.hush.hee.util.ObjectEncryption;
import com.hush.pgp.AlgorithmFactory;
import com.hush.pgp.DataFormatException;
import com.hush.pgp.InvalidSignatureException;
import com.hush.pgp.Key;
import com.hush.pgp.KeyFlags;
import com.hush.pgp.KeyGenerator;
import com.hush.pgp.Keyring;
import com.hush.pgp.MissingSelfSignatureException;
import com.hush.pgp.PgpConstants;
import com.hush.pgp.S2kAlgorithm;
import com.hush.pgp.Signable;
import com.hush.pgp.Signature;
import com.hush.pgp.SignatureSubpacket;
import com.hush.pgp.UserID;
import com.hush.pgp.Key.KeyType;
import com.hush.pgp.io.ArmorInputStream;
import com.hush.pgp.io.PgpMessageInputStream;
import com.hush.pgp.io.PgpMessageOutputStream;
import com.hush.util.Conversions;
import com.hush.util.EmailAddress;
import com.hush.util.ExceptionWrapper;
import com.hush.util.Logger;
import com.hush.util.UnrecoverableKeyException;
import com.sun.org.apache.regexp.internal.recompile;

/**
 * This class provides an interface to the Hush Key Server Network.
 *
 * Note that "aliases" are, in general, RFC822 email addresses.  However,
 * they are extended to support UTF8 character encoding.
 */
public class KeyManagementServices implements PgpConstants, Serializable
{

	private static final long serialVersionUID = -875499322111131947L;

	private static final String caCertificateString =
		"9901a2043a8beb0d110400fd7f53811d75122952df4a9c2eece4e7f611b7523ce"
		+ "f4400c31e3f80b6512669455d402251fb593d8d58fabfc5f5ba30f6cb9b556cd78"
		+ "13b801d346ff26660b76b9950a5a49f9fe8047b1022c24fbba9d7feb7c61bf83b5"
		+ "7e7c6a8a6150f04fb83f6d3c51ec3023554135a169132f675f3ae2b61d72aeff22"
		+ "203199dd14801c700a09760508f15230bccb292b982a2eb840bf0581cf50400f7e"
		+ "1a085d69b3ddecbbcab5c36b857b97994afbbfa3aea82f9574c0b3d07826751595"
		+ "78ebad4594fe67107108180b449167123e84c281613b7cf09328cc8a6e13c167a8"
		+ "b547c8d28e0a3ae1e2bb3a675916ea37f0bfa213562f1fb627a01243bcca4f1bea"
		+ "8519089a883dfe15ae59f06928b665e807b552564014c3bfecf492a0400a57f99e"
		+ "9e49b5488c7380d330bf47a2b3f20abb161404c372745ef1248016a5bb22e7a796"
		+ "dd10ef2b79f48f6bbeee1a02216d506595175f19066db6d3495842f3253f805f07"
		+ "8df2abdad074bf2f421a71ceb079d562a9005a74e8dd1adbbc5c00bfd931226a5a"
		+ "2bc72cd82b7f4c5ad36b8c9053e8ace3a5a6d219edab039f0288861041f1102002"
		+ "105023a8beb0e020701170c80118a60656fc2634b9cdaa2a73c7a02f9e7274cb62"
		+ "9000a09107a02f9e7274cb6293b99009f6920ec0c5e7d626ac5164ec76a7f6a8a7"
		+ "52f4c56009e322d0cfeb3a84ab142aae5f93549eb4e410b580fb41a48757368204"
		+ "36f6d6d756e69636174696f6e2044454d4f204341885004131102001005023a8be"
		+ "b0e020b0302150203160100000a09107a02f9e7274cb6298541009f7afb30f042d"
		+ "899deb4e4dcf488b29f5dbffae03e009f6861269734e2565a0c7c829d4a7564027"
		+ "9d6ddb0";
	
	private static Key staticCACertificate;

	private static Key _getStaticCaCertificate()
	{
		if ( staticCACertificate == null )
		{
			try
			{
				byte[] caKeyBytes =
				Conversions.hexStringToBytes(caCertificateString);
				Keyring caKeyring = new Keyring();
				caKeyring.load(new ByteArrayInputStream(caKeyBytes));
				staticCACertificate = (caKeyring.getKeys(null))[0];
			}
			catch (Exception e)
			{
				throw ExceptionWrapper.wrapInRuntimeException(
						"ERROR: Failed to decode CA certificate", e);
			}
		}
		return staticCACertificate;
	}

	/**
	 * The character encoding to use to interpret Strings.
	 */
	public static final String characterEncoding = "UTF8";

	public static final int LEGACY_PRIVATE_ALIAS_HASH_ALGORITHM = HASH_SHA1;
	public static final int LEGACY_PRIVATE_ALIAS_ITERATION_COUNT = 1048576;

	public static final int DEFAULT_PRIVATE_ALIAS_ITERATION_COUNT = 65536;
	public static final int DEFAULT_PRIVATE_ALIAS_HASH_ALGORITHM = HASH_SHA256;
	
	public static final int RANDOM_SEED_LENGTH = 16;
	
	private transient byte[] internalPassword;
	
	private transient Vector cachedPasswords = new Vector();
	
	public void setUsePublicKeyCache(boolean usePublicKeyCache)
	{
		this.usePublicKeyCache = usePublicKeyCache;
	}
	
	public static String makePrivateAlias(String alias, byte[] passphrase)
	{
		return makePrivateAlias(alias, passphrase,
				DEFAULT_PRIVATE_ALIAS_HASH_ALGORITHM,
				DEFAULT_PRIVATE_ALIAS_ITERATION_COUNT);
	}
	
	public static String makeLegacyPrivateAlias(String alias, byte[] passphrase)
	{
		return makePrivateAlias(alias, passphrase,
				LEGACY_PRIVATE_ALIAS_HASH_ALGORITHM,
				LEGACY_PRIVATE_ALIAS_ITERATION_COUNT);
	}
	
	public static String makePrivateAlias(String alias, byte[] passphrase,
			int hashAlgo, int count)
	{
		if (alias != null)
			alias = alias.toLowerCase();

		LineInterpolation.validateSecret(passphrase);
		
		// Creating the private alias is done by repeatedly hashing (SHA1) the alias
		// plus passphrase concatenated with a '\n' in between for uniqueness. 
		// The total number of bytes hashed should be 2^20.
		// This all is equivalent to using the S2kAlgorithm implementation used with PGP
		// HashAlg: SHA1
		// Salt:	alias + '\n'    (longer than 8 bytes but S2kAlgorithm doesn't care)
		// Count:   0xA0 encoded meaning 2^20
		// OutputKeyLength:  20 bytes i.e. the full SHA1 hash output.
		// Make S2k 'salt'
		byte[] aliasBytes =
			Conversions.stringToByteArray(alias, characterEncoding);
		byte[] aliasPlusEndOfLineBytes = new byte[aliasBytes.length + 1];
		System.arraycopy(
			aliasBytes,
			0,
			aliasPlusEndOfLineBytes,
			0,
			aliasBytes.length);
		aliasPlusEndOfLineBytes[aliasPlusEndOfLineBytes.length - 1] =
			(byte) '\n';
		S2kAlgorithm alg =
			new S2kAlgorithm(
				S2kAlgorithm.S2K_TYPE_ITERATED_AND_SALTED,
				hashAlgo,
				aliasPlusEndOfLineBytes,
				count);
		byte[] privateAlias = alg.s2k(passphrase, HASH_LENGTHS[hashAlgo]);
		return Conversions.bytesToHexString(privateAlias);
	}

	private Keyserver keyserver;
	
	/**
	 * The applicationID is an integer reference to the application that generates
	 * the key.  It defaults to zero, which assumes generically generated by the SDK.
	 */
	private int applicationID = 0;

	/**
	 * A Hashtable storing key records for public keys
	 * that have been looked up, if the cache is on.
	 */
	public Vector certificateKeyRecords = new Vector();

	/**
	 * Anyone attempting to register an alias in a specific domain (namespace) must submit
	 * the customer ID corresponding to that domain.
	 */
	private String customerID;

	/**
	 * A Hashtable storing key records for authenticated
	 * private keys.
	 */
	private transient Hashtable keyRecords;

	/**
	 * A pseudo-random number generator for use by this class.
	 */
	private SecureRandomCallback secureRandomCallback;

	/**
	 * A variable for storing the key records in encrypted form when the
	 * class is serialized.
	 */
	private byte[] encryptedKeyRecords;
	
	/**
	 * A variable for storing the cached passwords in encrypted form when
	 * the class is serialized.
	 */
	private byte[] encryptedCachedPasswords;

	private boolean forgiveBadRandomSeed = false;

	private boolean usePublicKeyCache = true;
	
	private int newPrivateAliasIterationCount = DEFAULT_PRIVATE_ALIAS_ITERATION_COUNT;
	private int newPrivateAliasHashAlgorithm = DEFAULT_PRIVATE_ALIAS_HASH_ALGORITHM;
	private int newEncryptionKeyAlgorithm = CIPHER_RSA;
	private int newEncryptionKeySize = 2048;
	private int newSigningKeyAlgorithm = CIPHER_RSA;
	private int newSigningKeySize = 2048;
	private int newKeySignatureHashAlgorithm = HASH_SHA1;
	private int newKeySymmetricAlgorithm = CIPHER_AES256;
	private boolean enableRSAKeyUpgrade = false;
	private Key caCertificate = null;
	
	public KeyManagementServices(SecureRandomCallback secureRandomCallback)
	{
		super();
		this.secureRandomCallback = secureRandomCallback;
	}
	
	public void setKeyserver(Keyserver keyserver)
	{
		this.keyserver = keyserver;
	}
	
	public boolean activateKeyRecord(String alias, String activationKey)
		throws KeyStoreException
	{
		if (alias != null)
			alias = alias.toLowerCase();

		keyserver.activateUser(alias, activationKey);
		
		return true;
	}

	public String[] changePassphrase(
		String alias,
		byte[] oldPassphrase,
		byte[] newPassphrase)
		throws KeyStoreException, UnrecoverableKeyException, IOException
	{

		if (alias != null)
			alias = alias.toLowerCase();

		// Ensure this passphrase will work with secret sharing
		LineInterpolation.validateSecret(newPassphrase);
		
		// Find record
		KeyRecord keyRecord = null;

		// see if it is cached?
		keyRecord = null;
		try
		{
			keyRecord = retrievePrivateKeyRecord(alias, null);
		}
		catch (UnrecoverableKeyException e)
		{
		}

		if (keyRecord != null)
		{
			// verify that the passphrase is correct.
			String cachedPrivateAlias = keyRecord.privateAlias;

			String constructedPrivateAlias =
				makePrivateAlias(alias, oldPassphrase,
						keyRecord.privateAliasHash,
						keyRecord.privateAliasIterationCount);

			if (!cachedPrivateAlias.equals(constructedPrivateAlias))
			{
				throw new UnrecoverableKeyException("Passphrase is not valid");
			}
		}
		else
		{
			keyRecord = retrievePrivateKeyRecord(alias, oldPassphrase);
		}

		PrivateKey privateKey = new com.hush.hee.keyserver.PrivateKey();
		privateKey.setEncryptedPrivateKey(EncryptedPrivateKeyPackage
				.makePrivateKeyPackage(keyRecord.privateKeyring, newPassphrase,
						getRandom(), newKeySymmetricAlgorithm,
						newPrivateAliasHashAlgorithm,
						newPrivateAliasIterationCount));
		
		keyserver.savePrivateKeyInformation(keyRecord.privateAlias, makePrivateAlias(
				alias, newPassphrase, keyRecord.privateAliasHash,
				keyRecord.privateAliasIterationCount),
				new PrivateKey[] { privateKey }, null, Boolean.FALSE);
		
		removePrivateKeyRecord(alias);

		retrievePrivateKeyRecord(alias, newPassphrase);
		
		if (usesSharedSecret(alias))
		{
			String[] shadows = PassphraseComponents.makeShadows(newPassphrase,
					getRandom());
			keyserver.savePassphraseComponent(alias, shadows[0]);
			String[] returnShadows = new String[]
			{ shadows[1], shadows[2] };
			return returnShadows;
		}

		return null;
	}

	public void checkCertificate(Key key, long time)
		throws KeyStoreException, InvalidSignatureException
	{
		Key mainKey = key.getMainKey();
		// First, check to see that there is a user ID signed by the CA.

		UserID[] verifiedUserIDs =
			mainKey.getVerifiedCertifications(getCaCertificate(), time);
		if (verifiedUserIDs.length == 0)
			throw new KeyStoreException(
				"This key is not certified by the Hush CA: "
					+ Conversions.bytesToHexString(key.getKeyID()));
		for (int x = 0; x < verifiedUserIDs.length; x++)
		{
			// Make sure the userID is not revoked
			if (verifiedUserIDs[x]
				.verifySignatures(
					getCaCertificate(),
					new int[] { Signature.SIGNATURE_KEY_REVOCATION },
					time,
					false)
				.length
				> 0)
			{
				throw new KeyStoreException(
					"The alias was revoked by the Hush CA: "
						+ verifiedUserIDs[x].toString());
			}
			// Make sure the userID is not revoked
			if (verifiedUserIDs[x]
				.verifySignatures(
					mainKey,
					new int[] { Signature.SIGNATURE_KEY_REVOCATION },
					time,
					false)
				.length
				> 0)
			{
				throw new KeyStoreException(
					"The alias was revoked by a self-signature: "
						+ verifiedUserIDs[x].toString());
			}
		}
		if (mainKey
			.verifySignatures(
				getCaCertificate(),
				new int[] { Signature.SIGNATURE_KEY_REVOCATION },
				time,
				false)
			.length
			> 0)
		{
			throw new KeyStoreException(
				"The main key for this alias was revoked by the Hush CA: "
					+ verifiedUserIDs[0].toString());
		}
		if (mainKey
			.verifySignatures(
				mainKey,
				new int[] { Signature.SIGNATURE_KEY_REVOCATION },
				time,
				false)
			.length
			> 0)
		{
			throw new KeyStoreException(
				"The main key for this alias was revoked by a self-signature: "
					+ verifiedUserIDs[0].toString());
		}
		if (key != mainKey)
		{
			if (key
				.verifySignatures(
					getCaCertificate(),
					new int[] { Signature.SIGNATURE_KEY_REVOCATION },
					time,
					false)
				.length
				> 0)
			{
				throw new KeyStoreException(
					"The encryption key for this alias was revoked by the Hush CA: "
						+ verifiedUserIDs[0].toString());
			}
			if (key
				.verifySignatures(
					mainKey,
					new int[] { Signature.SIGNATURE_KEY_REVOCATION },
					time,
					false)
				.length
				> 0)
			{
				throw new KeyStoreException(
					"The encryption key for this alias was revoked by a self-signature: "
						+ verifiedUserIDs[0].toString());
			}
		}
	}

	public void clearPrivateKeyRecord(String alias)
	{
		if ( keyRecords == null ) return;
		keyRecords.remove(alias);	
	}
	
    public String[] createKeyRecord(
            String alias,
            byte[] passphrase,
            String preActivationCode,
            boolean useSharedSecret)
            throws KeyStoreException
    {
        return createKeyRecord(alias, passphrase, preActivationCode,
                useSharedSecret, null);
    }
    
	public String[] createKeyRecord(
		String alias,
		byte[] passphrase,
		String preActivationCode,
		boolean useSharedSecret,
        String encryptionMethod)
		throws KeyStoreException
	{
		String[] shadows = null;

		if (alias != null)
			alias = alias.toLowerCase();
        
		// Ensure this passphrase will work with secret sharing
		LineInterpolation.validateSecret(passphrase);
		
		KeyRecord keyRecord = new KeyRecord();

		keyRecord.alias = alias;

		keyRecord.privateAliasHash = newPrivateAliasHashAlgorithm;
		keyRecord.privateAliasIterationCount = newPrivateAliasIterationCount;
		
		keyRecord.privateAlias = makePrivateAlias(alias, passphrase,
				keyRecord.privateAliasHash,
				keyRecord.privateAliasIterationCount);
		
		

		KeyGenerator generator = createKeyGenerator();

		Key key =
			generator.generateKey("\"" + alias + "\" <" + alias + ">", null);
		
		Keyring tmpPublicKeyring = new Keyring();

		Keyring tmpPrivateKeyring = new Keyring();
		tmpPrivateKeyring.addKey(key);
		tmpPublicKeyring.addKey(key);

		String keyID;

		try
		{

			keyID =
				Conversions.bytesToHexString(
					(tmpPublicKeyring.getKeys(alias)[0]).getKeyID());
		}
		catch (MissingSelfSignatureException e)
		{
			throw ExceptionWrapper.wrapInRuntimeException("Should never happen", e);
		}
		catch (InvalidSignatureException e)
		{
			throw ExceptionWrapper.wrapInRuntimeException("Should never happen", e);
		}

		String shadow = null;
		if (useSharedSecret)
		{
			String[] allShadows = PassphraseComponents.makeShadows(passphrase,
					getRandom());
			shadows = new String[]
			{ allShadows[1], allShadows[2] };
			shadow = allShadows[0];
		}

		PrivateKey privateKey = new com.hush.hee.keyserver.PrivateKey();
		privateKey.setEncryptedPrivateKey(EncryptedPrivateKeyPackage.makePrivateKeyPackage(tmpPrivateKeyring, passphrase,
						getRandom(), newKeySymmetricAlgorithm,
						newPrivateAliasHashAlgorithm,
						newPrivateAliasIterationCount));
		
		keyserver.savePrivateKeyInformation(keyRecord.privateAlias, null,
					new PrivateKey[]{privateKey}, makeRandomSeed(key, getRandom()),
					null);
		
		PublicKey publicKey = new PublicKey();
		publicKey.setKey(tmpPublicKeyring.toString());
		publicKey.setKeyID(keyID);
		
		keyserver.savePublicKeyInformation(alias,
					new PublicKey[]{publicKey},
					preActivationCode,
					customerID,
					String.valueOf(applicationID),
					new IteratedAndSaltedPrivateAliasDefinition(
					PgpConstants.HASH_STRINGS[keyRecord.privateAliasHash],
					new Integer(keyRecord.privateAliasIterationCount),
					"Hex").toString(),
					encryptionMethod,
					shadow);

		keyRecord.privateKeyring.addKey(key);
		setPrivateKeyRecord(alias, keyRecord);

		return shadows;
	}
	
	private KeyRecord findCached(String alias, String keyID)
	{
		Enumeration e = certificateKeyRecords.elements();
		while (e.hasMoreElements())
		{
			KeyRecord next = (KeyRecord) e.nextElement();

			if (alias != null && alias.equalsIgnoreCase(next.alias))
			{
				return next;
			}

			if (keyID != null)
			{
				try
				{
					Key publicKey =
						next.publicKeyring.getKey(
							Conversions.hexStringToBytes(keyID));
					if (publicKey != null)
						return next;
				}
				catch (InvalidSignatureException p)
				{
					Logger.logThrowable(this, Logger.WARNING,
							"Invalid signature reading public key", p);
				}
				catch (MissingSelfSignatureException p)
				{
					Logger.logThrowable(this, Logger.WARNING,
							"Missing self signature reading public key", p);
				}
			}
		}
		return null;
	}

	public void cachePasswords(byte[][] passwords)
	{
		if ( passwords == null ) return;
		if ( cachedPasswords == null )
			cachedPasswords = new Vector();
		for (int x=0; x<passwords.length; x++)
		{
			if ( passwords[x] != null )
			{
				cachedPasswords.addElement(passwords[x]);	
			}
		}
	}
	
	public byte[][] getCachedPasswords()
	{
		if ( cachedPasswords == null ) return new byte[0][];
		byte[][] myArray = new byte[cachedPasswords.size()][];
		cachedPasswords.copyInto(myArray);
		return myArray;
	}

    public int getCachedPasswordCount()
	{
    	if ( cachedPasswords == null ) return 0;
		return cachedPasswords.size();
	}
	
	public String[] getCertifiedAliases(Key key, long time)
		throws InvalidSignatureException
	{
		Vector verified = new Vector();
		UserID[] userIDs = key.getVerifiedCertifications(getCaCertificate(), time);
		for (int x = 0; x < userIDs.length; x++)
		{
			verified.addElement(userIDs[x].toString());
		}
		String[] returnValue = new String[verified.size()];
		verified.copyInto(returnValue);
		return returnValue;
	}

	public String getCustomerID()
	{
		return customerID;
	}

	/**
	 * Finds the most recent, non-revoked encryption key
	 * and returns it, or null if one is not found.  It's a hack that
	 * ignores expiration times.
	 * <br>
	 * If you want to use a key for encryption that is revoked or no longer
	 * valid, select it manually, not using this method.
	 * <br>
	 * This goes only by the algorithm type, not by the usage convention signature
	 * packet which may or may not exist.
	 * <br>
	 * This will not return keys for experimental algorithms such as Elliptic
	 * Curve or X9.42.
	 * <br>
	 * This will not verify any signatures.  Those have to be checked separately.
	 * 
	 * @return the encryption key
	 */
	public Key getEncryptionKey(Key key)
	{
		if ((key.getAlgorithm() == CIPHER_RSA
			|| key.getAlgorithm() == CIPHER_RSA_ENCRYPT_ONLY
			|| key.getAlgorithm() == CIPHER_ELGAMAL_ENCRYPT_ONLY
			|| key.getAlgorithm() == CIPHER_ELGAMAL)
			&& !key.isRevoked())
		{
			return key;
		}
		Key returnValue = null;
		Key[] subkeys = key.getSubkeys();
		Key thisKey;
		for (int x = 0; x < subkeys.length; x++)
		{
			thisKey = getEncryptionKey(subkeys[x]);
			if (returnValue == null
				|| thisKey.getCreationTime() > returnValue.getCreationTime())
				returnValue = thisKey;
		}
		return returnValue;
	}
	
	/**
	 * Call this to verify if the keys need to be upgraded to the latest version.
	 * @param alias
	 * @param passphrase
	 * @param privateKey
	 * @param publicKey
	 * @return True if changes were made
	 * @throws KeyStoreException
	 * @throws IOException
	 */
	public boolean validateAndUpgradeKeys(String alias, byte[] passphrase, Key privateKey, 
			Key publicKey) throws KeyStoreException, IOException
	{
		// EXPIRATION DATE FIX **********************

		boolean modifiedPublicKey = false;
		boolean modifiedPrivateKey = false;

		Key[] subkeys = publicKey.getSubkeys();

		for (int x = 0; x < subkeys.length; x++)
		{
			if (stripExpirationDate(subkeys[x], privateKey))
				modifiedPublicKey = true;
		}

		UserID[] userIDs = publicKey.getUserIDs();

		for (int x = 0; x < userIDs.length; x++)
		{
			if (stripExpirationDate(userIDs[x], privateKey))
				modifiedPublicKey = true;
		}
		// EXPIRATION DATE FIX **********************						
		// RSA ENCRYPTION\SIGN ALGORITHM FIX **********************
		// We only check for RSA encrypt only and RSA sign only. Older algorithms are ignored if they do not have the the correct flags
		// new keys will always be generated with the new flags regardless of the algorithm used
		if (enableRSAKeyUpgrade && (privateKey.getAlgorithm() == 
			PgpConstants.CIPHER_RSA_SIGN_ONLY || privateKey.getAlgorithm() == 
				PgpConstants.CIPHER_RSA_ENCRYPT_ONLY) && passphrase != null && 
				passphrase.length > 0)
		{
			// We need to generate a new key set for this user.
			generateAndAddNewKey(alias, passphrase);
			return true;	// Skip the rest as this code will have saved any previous changes
		}
		// RSA ENCRYPTION\SIGN ALGORITHM FIX **********************
		if (modifiedPrivateKey && passphrase != null && passphrase.length > 0)
		{
			KeyRecord record = retrievePrivateKeyRecord(alias, passphrase);
			Keyring newKeyring = new Keyring();
			newKeyring.addKey(privateKey);
			PrivateKey privateKeyObj = new com.hush.hee.keyserver.PrivateKey();
			privateKeyObj.setEncryptedPrivateKey(EncryptedPrivateKeyPackage
					.makePrivateKeyPackage(newKeyring, passphrase,
							getRandom(), newKeySymmetricAlgorithm,
							newPrivateAliasHashAlgorithm,
							newPrivateAliasIterationCount));
			
			keyserver.savePrivateKeyInformation(record.privateAlias, null, 
					new PrivateKey[] { privateKeyObj }, null, Boolean.TRUE);
			
			removePrivateKeyRecord(alias);
			
			retrievePrivateKeyRecord(alias, passphrase);
		}		
		if (modifiedPublicKey)
		{
			Keyring newKeyring = new Keyring();
			newKeyring.addKey(publicKey);
			PublicKey publicKeyObj = new PublicKey();
			publicKeyObj.setKeyID(Conversions
					.bytesToHexString(publicKey.getKeyID()));
			publicKeyObj.setKey(newKeyring.toString());
			keyserver.savePublicKeyInformation(alias, 
					new PublicKey[]{ publicKeyObj }, null, 
					null, null, null, null, null);
		}
		
		return modifiedPrivateKey | modifiedPublicKey;
	}

	public Key getPrivateKey(String alias, byte[] passphrase)
		throws KeyStoreException, UnrecoverableKeyException, IOException
	{
		try
		{
			if (alias != null)
				alias = alias.toLowerCase();

			Key publicKey = getPublicKey(alias, null);

			if (publicKey == null)
				throw new UnrecoverableKeyException(
					"No public key for " + alias);
			
			KeyRecord record = retrievePrivateKeyRecord(alias, passphrase);
			
			if (record == null)
				return null;

			Key privateKey = record.privateKeyring.getKey(publicKey.getKeyID());
			
			if ( privateKey == null )
			{
				clearPrivateKeyRecord(alias);
				throw new UnrecoverableKeyException(
					"No private key found that matches public key for " + alias);
			}
			
			return privateKey;

		}
		catch (InvalidSignatureException e)
		{
			clearPrivateKeyRecord(alias);
			throw KeyStoreException.wrapInKeyStoreException("Invalid signature",
					e);
		}
		catch (MissingSelfSignatureException e)
		{
			clearPrivateKeyRecord(alias);
			throw KeyStoreException.wrapInKeyStoreException(
					"Missing self signature", e);
		}
	}

	/**
	 * Gets a clone of the internal private keyring that has all keys
	 * decrypted.  This is a *clone*.  Keys added to this keyring will
	 * not be added to the internal cached key record.
	 */
	public Keyring getPrivateKeyring(String alias, byte[] passphrase)
		throws KeyStoreException, IOException, UnrecoverableKeyException
	{
		if (alias != null)
			alias = alias.toLowerCase();
		KeyRecord record = retrievePrivateKeyRecord(alias, passphrase);
		if (record == null)
			return null;
		return record.privateKeyring;
	}

	/**
	 * Returns the appropriate method of encryption for each alias, such as a KeyRecord
	 * or a GeneratedPassword.  In the future, it may return a QuestionAndAnswer too. 
	 * @param list of aliases
	 * @return encryption objects, such as KeyRecords or GeneratedPasswords.
	 */
	public Hashtable getEncryptionObjects(String[] aliasess) throws KeyStoreException, NoEncryptionMethodException,
		InvalidSignatureException, IOException
	{
		Hashtable objects = new Hashtable();
		
		for (int i = 0; i < aliasess.length; i++)
		{
			if ( aliasess[i] == null )
				throw new KeyStoreException("Unexpected null alias at recipient array position " + i);
			String alias = aliasess[i].trim().toLowerCase();
			if ( "".equals(alias) )
				throw new KeyStoreException("Unexpected empty string alias at recipient array position " + i);
			
			if ( objects.get(alias) != null )
			{
				Logger.log(this, Logger.WARNING, "The same alias exists in the array twice: " + alias);
				continue;
				//throw new IllegalArgumentException("The same alias exists in the array twice: " + aliases[i]);
			}
			objects.put(alias, getEncryptionObject(alias));
		}
		return objects;
	}
	
	private Object getEncryptionObject(String alias) throws KeyStoreException, IOException, InvalidSignatureException
	{
		KeyRecord record = retrievePublicKeyRecord(alias, null);
		if (record == null)
		{
			throw new NoEncryptionMethodException(
					"No encryption method found for: " + alias);
		}
		
		Key key = getPublicKeyFromRecord(record, null);
		if (key != null)
		{
			if (record.encryptionMethod != null &&
					record.encryptionMethod.equals(KeyRecord.NONE))
			{
				throw new NoEncryptionMethodException(
						"No public key found for encryption: " + alias);
			}
			
			checkCertificate(key,
				System.currentTimeMillis() / 1000);
			return record;
		}

		if (record != null && record.generatedPassword != null)
		{
			String genRecipient = record.generatedPassword.getPasswordRecipient();
			if (genRecipient != null)
			{
				Key generatePasswordKey = getPublicKey(genRecipient,
						null);
				if (generatePasswordKey == null)
					throw new NoEncryptionMethodException(
							"No public key found for generated password recipient: "
									+ genRecipient);
				checkCertificate(generatePasswordKey, System.currentTimeMillis() / 1000);			
			}
			return record.generatedPassword;
		}

		throw new NoEncryptionMethodException(
					"No encryption object found for: " + alias);
	}
	
	protected Key getPublicKeyFromRecord(KeyRecord record, String keyID)
		throws KeyStoreException
	{
		try
		{
			String alias = record.alias;
			if (keyID != null)
				return record.publicKeyring.getKey(
						Conversions.hexStringToBytes(keyID));
			// Return the most recently created key.
			Key returnValue = null;
			Key[] possibleKeys = record.publicKeyring.getKeys(alias);
			for (int x = 0; x < possibleKeys.length; x++)
			{
				if (returnValue == null
					|| possibleKeys[x].getCreationTime()
						> returnValue.getCreationTime())
				{
					returnValue = possibleKeys[x];
				}
			}
			return returnValue;
		}
		catch (InvalidSignatureException e)
		{
			throw KeyStoreException.wrapInKeyStoreException("Invalid signature",
					e);
		}
		catch (MissingSelfSignatureException e)
		{
			throw KeyStoreException.wrapInKeyStoreException(
					"Missing self signature", e);
		}
	}
	
	
	/**
	 * Returns the most recently created public key.
	 * 
	 * @param alias the alias or null
	 * @param keyID the key ID or null
	 * @return the most recent public key
	 * @throws KeyStoreException
	 */
	public Key getPublicKey(String alias, String keyID)
		throws KeyStoreException, IOException
	{
		if (alias != null)
			alias = alias.toLowerCase();

		KeyRecord record = retrievePublicKeyRecord(alias, keyID);

		if (record == null)
			return null;
		
		return getPublicKeyFromRecord(record, keyID);
	}

	public Key[] getPublicKeys(String alias)
		throws KeyStoreException, IOException
	{
		try
		{

			if (alias != null)
				alias = alias.toLowerCase();

			KeyRecord record = retrievePublicKeyRecord(alias, null);
			if (record == null)
				return null;
			return record.publicKeyring.getKeys(alias);

		}
		catch (InvalidSignatureException e)
		{
			throw KeyStoreException.wrapInKeyStoreException("Invalid signature",
					e);
		}
		catch (MissingSelfSignatureException e)
		{
			throw KeyStoreException.wrapInKeyStoreException(
					"Missing self signature", e);
		}
	}
	
	public SecureRandom getRandom()
	{
		return secureRandomCallback.getSecureRandom();
	}
	
	public String importCertificate(
		String pgpCert,
		String alias,
		String activationCode)
		throws
			KeyStoreException,
			IOException,
			InvalidSignatureException,
			MissingSelfSignatureException
	{
		if (alias != null)
			alias = alias.toLowerCase();

		Keyring keyring = new Keyring();
		keyring.load(
			new ByteArrayInputStream(
				Conversions.stringToByteArray(pgpCert, UTF8)));
		Key[] keys = keyring.getKeys(alias);

		if (keys.length == 0)
			throw new KeyStoreException("No user ID's match the alias");

		if (keys.length > 1)
			throw new KeyStoreException("Public key block contains more than one key matching the alias");

		// Remove all but the one user ID from the key being uploaded
		UserID[] userIDs = keys[0].getUserIDs();
		for (int x = 0; x < userIDs.length; x++)
		{
			EmailAddress e = EmailAddress.parseRecipient(userIDs[x].toString());
			if (e.getEmailAddress() == null
				|| !e.getEmailAddress().toLowerCase().equals(alias))
			{
				keys[0].removeUserID(userIDs[x]);
			}
		}

		userIDs = keys[0].getUserIDs();
		if (userIDs.length == 0)
			throw new KeyStoreException("Public key block contains no user ID matching the alias");

		Keyring uploadKeyRing = new Keyring();
		uploadKeyRing.addKey(keys[0]);
	
		String publicKeyPackage = uploadKeyRing.toString();
		String keyId = Conversions.bytesToHexString(keys[0].getKeyID());
		
		PublicKey publicKey = new PublicKey();
		publicKey.setKeyID(keyId);
		publicKey.setKey(publicKeyPackage);
		
		keyserver.savePublicKeyInformation(alias, new PublicKey[]
		{ publicKey }, activationCode, customerID, String
				.valueOf(applicationID), null, null, null);
		
		return alias;
	}

	/**
	 * Inject randomness to the SecureRandom instance cached in KMS.
	 * <BR>
	 * Creation date: (19/12/2000 13:24:43)
	 * @param randomData byte[]
	 */
	public void injectEntropy(byte[] randomData)
	{
		getRandom().setSeed(randomData);
	}

	public boolean isAliasAvailable(String alias)
		throws KeyStoreException
	{

		if (alias != null)
			alias = alias.toLowerCase();

		PublicKeyInformation publicKeyInformation;
		

		publicKeyInformation = keyserver.getPublicKeyInformation(alias, null, true);
		if (publicKeyInformation == null)
			return true;
		
		// TODO: use constant
		if ("Needs Activation".equals(publicKeyInformation.getUserStatus()))
		{
			return true;
		}
		
		return false;
	}

	private void loadEncryptedRandomSeed(String encryptedRandomSeed, KeyRecord record)
			throws IOException, KeyStoreException, InvalidSignatureException,
			MissingSelfSignatureException
	{
		PgpMessageInputStream decryptionStream = new PgpMessageInputStream(
				new ArmorInputStream(new ByteArrayInputStream(Conversions
						.stringToByteArray(encryptedRandomSeed, UTF8))));
		ByteArrayOutputStream decryptedRandomSeed = new ByteArrayOutputStream();
		decryptionStream.addKeyring(record.privateKeyring);

		int x;
		while ((x = decryptionStream.read()) != -1)
			decryptedRandomSeed.write(x);
		decryptionStream.close();
		Signature[] sigs = decryptionStream.getSignatures();
		if (sigs.length == 0)
		{
			throw new KeyStoreException("The random seed has no signature");
		}
		sigs[0].finishVerification(record.privateKeyring.getKey(sigs[0]
				.getIssuerKeyID(false)));
		byte[] randomSeed = decryptedRandomSeed.toByteArray();
		getRandom().setSeed(randomSeed);
	}
	
	public static String makeRandomSeed(Key key, SecureRandom random)
	{
		try
		{
			byte[] randomSeed = new byte[RANDOM_SEED_LENGTH];
			random.nextBytes(randomSeed);
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			PgpMessageOutputStream encryption =
				new PgpMessageOutputStream(out, random);

			// This is so Hush Messenger (still using old HEE) won't break
			// 2004-03-31
			encryption.setUseMdc(false);

			encryption.setSymmetricCipher(CIPHER_AES256);
			encryption.setUseArmor(true);
			encryption.addRecipient(key, null, true);
			encryption.addOnePassSigner(key);
			encryption.write(randomSeed);
			encryption.close();

			return Conversions.byteArrayToString(out.toByteArray(), UTF8);
		}
		catch (IOException e)
		{
			throw ExceptionWrapper.wrapInRuntimeException("Should never happen", e);
		}
	}
	
	/**
	 * This method allows a KMS to be set up without specifying a secure
	 * random, but until a seed is given, a null pointer exception would
	 * be thrown.
	 */
	/*
	public void seedRandom(byte[] randomSeed)
	{
		if ( random == null )
			random = new SHA1BlumBlumShubRandom();
		random.setSeed(randomSeed);
	}
	*/


	/**
	 * This will return the private key record for an alias.
	 * <p>
	 * If the key record is cached and the passphrase is null, the key record
	 * is returned.  If a passphrase is given, though, it is checked to see if it
	 * matches the cached record.
	 * <p>
	 * This method will never return null.
	 */
	public KeyRecord retrievePrivateKeyRecord(String alias, byte[] passphrase)
		throws IOException, KeyStoreException, UnrecoverableKeyException
	{

		try
		{
			if (alias == null)
				return null;
			alias = alias.toLowerCase();
			KeyRecord record = getPrivateKeyRecord(alias);
			if (record != null)
			{
				if (passphrase != null)
				{
					if (!record
						.privateAlias
						.equalsIgnoreCase(makePrivateAlias(alias, passphrase,
								record.privateAliasHash, record.privateAliasIterationCount)))
					{
						throw new UnrecoverableKeyException("Passphrase does not match passphrase for cached record");
					}
				}
				return record;
			}

			if (passphrase == null)
				throw new UnrecoverableKeyException("Passphrase is null");

			record = new KeyRecord();
			record.alias = alias;
			getPrivateAliasDefinition(record);
			
			
			record.privateAlias = makePrivateAlias(alias, passphrase,
					record.privateAliasHash,
					record.privateAliasIterationCount);
			
			PrivateKeyInformation privateKeyInformation;
			
			try
			{
				privateKeyInformation = keyserver.getPrivateKeyInformation(record.privateAlias,
						Boolean.TRUE);
			}
			catch (DeniedException e)
			{
				throw UnrecoverableKeyException.wrap("Invalid passphrase for "
						+ alias, e);
			}

			Date lastAccessDate = privateKeyInformation.getLastAccessTime();
			record.lastAccessTime = ( lastAccessDate == null ? 0 : lastAccessDate.getTime() / 1000);
			String encryptedRandomSeed = privateKeyInformation.getEncryptedRandomSeed();
			PrivateKey[] privateKeys = privateKeyInformation.getEncryptedPrivateKeys();

			for(int i=0; i<privateKeys.length; i++)
			{
				EncryptedPrivateKeyPackage.decryptPrivateKeyPackage(Conversions
						.stringToByteArray(privateKeys[i].getEncryptedPrivateKey(), UTF8),
						passphrase, record.privateKeyring);
			}

			record.privateKeyring.decryptSecretKeys(passphrase);

			try
			{

				if (encryptedRandomSeed != null)
				{
					loadEncryptedRandomSeed(encryptedRandomSeed, record);
				}
			}
			catch (IOException e)
			{
				if (!forgiveBadRandomSeed)
					throw e;
				else
				{
					Logger.logThrowable(this, Logger.WARNING,
						"Failure decrypting/verifying random seed", e);
				}
			}
			catch (KeyStoreException e)
			{
				if (!forgiveBadRandomSeed)
					throw e;
				else
				{
					Logger.logThrowable(this, Logger.WARNING,
						"Failure decrypting/verifying random seed", e);
				}
			}
			catch (InvalidSignatureException e)
			{
				if (!forgiveBadRandomSeed)
					throw e;
				else
				{
					Logger.logThrowable(this, Logger.WARNING,
						"Failure decrypting/verifying random seed", e);
				}
			}
			
			// Store in the hashtable for later use
			setPrivateKeyRecord(alias, record);

			return record;
		}
		catch (InvalidSignatureException e)
		{
			throw KeyStoreException.wrapInKeyStoreException("Invalid signature",
					e);
		}
		catch (MissingSelfSignatureException e)
		{
			throw KeyStoreException.wrapInKeyStoreException(
					"Missing self signature", e);
		}
	}

	public void getPrivateAliasDefinition(KeyRecord record)
	{
		IteratedAndSaltedPrivateAliasDefinition privateAliasDefinition = null;
		try
		{
			String privateAliasDefinitionString = keyserver
					.getPrivateAliasDefinition(record.alias);
			if (privateAliasDefinitionString != null)
				privateAliasDefinition = IteratedAndSaltedPrivateAliasDefinition
						.parseContents(privateAliasDefinitionString);
		}
		catch(KeyStoreException e)
		{
			Logger.logThrowable(this, Logger.WARNING, "Couldn't perform "
					+ "private alias definition lookup", e);
		}
		if ( privateAliasDefinition == null ||
				privateAliasDefinition.getHashAlgorithm() == null ||
				privateAliasDefinition.getCount() == null )
		{
			record.privateAliasHash = LEGACY_PRIVATE_ALIAS_HASH_ALGORITHM;
			record.privateAliasIterationCount = LEGACY_PRIVATE_ALIAS_ITERATION_COUNT;
		}
		else
		{
			record.privateAliasHash = AlgorithmFactory
					.getHashID(privateAliasDefinition.getHashAlgorithm());
			record.privateAliasIterationCount = privateAliasDefinition
					.getCount().intValue();
		}
	}

	public KeyRecord retrievePublicKeyRecord(String alias, String lookupKeyID)
		throws KeyStoreException, IOException
	{
		try
		{
			Logger.log(this, Logger.DEBUG,
					"Retrieving public key record");

			if (alias != null)
				alias = alias.toLowerCase();

			KeyRecord record = findCached(alias, lookupKeyID);
			if (record != null)
			{
				return record;
			}

			PublicKeyInformation publicKeyInformation =
				keyserver.getPublicKeyInformation(alias, lookupKeyID, true);
			
			if (publicKeyInformation == null)
			{
				return null;
			}
			
			if ( alias != null && !"Active".equals(publicKeyInformation.getUserStatus())
					&& publicKeyInformation.getGeneratedPassword() == null)
			{
				Logger.log(this, Logger.DEBUG,
					"Key server indicated that the alias is not active - "
						+ " returning null public key");
				return null;
			}

			record = new KeyRecord();
			record.alias = alias;
			record.sharedSecret =
				( publicKeyInformation.getPassphraseComponent() != null &&
						publicKeyInformation.getPassphraseComponent().booleanValue());
			record.generatedPassword = publicKeyInformation.getGeneratedPassword();
			record.encryptionMethod = publicKeyInformation.getEncryptionMethod();
			
			PublicKey[] publicKeys = publicKeyInformation.getPublicKeys();

			if (publicKeys == null)
				return record;

			for (int i = 0; i < publicKeys.length; i++)
			{
				if ( publicKeys[i].getIsAdk() )
				{
					loadKey(record.adkKeyring, publicKeys[i]);
				}
				else
				{
					loadKey(record.publicKeyring, publicKeys[i]);
				}
			}
			
			if (usePublicKeyCache)
				certificateKeyRecords.addElement(record);
			return record;
		}
		catch (DataFormatException e)
		{
			throw KeyStoreException.wrapInKeyStoreException("Data format error",
					e);
		}
	}
	
	private void loadKey(Keyring keyring, PublicKey key)
			throws DataFormatException, IOException
	{
		keyring.load(new ArmorInputStream(new ByteArrayInputStream(Conversions
				.stringToByteArray(key.getKey(), UTF8))));
	}

	public void clearPublicKeyCache()
	{
		certificateKeyRecords.removeAllElements();
	}
	
	public void setApplicationID(int applicationID)
	{
		this.applicationID = applicationID;
	}

	public void setCustomerID(String customerID)
	{
		this.customerID = customerID;
	}
	
	/**
	 * This method sets a variable that indicates that the system will tolerate
	 * damaged or missing random seed without throwing an exception.
	 */
	public void setForgiveBadRandomSeed(boolean forgiveBadRandomSeed)
	{
		this.forgiveBadRandomSeed = forgiveBadRandomSeed;
	}

	private boolean stripExpirationDate(Signable signable, Key privateKey)
	{
		boolean modified = false;

		Signature[] sigsByPrivKey = signable.getSignatures(-1, null);

		Signature sig;

		for (int y = 0; y < sigsByPrivKey.length; y++)
		{
			boolean thisSigModified = false;

			sig = sigsByPrivKey[y];

			SignatureSubpacket[] subpackets = sig.getHashedSubpackets();
			for (int x = 0; x < subpackets.length; x++)
			{
				if (subpackets[x].getType()
					== SignatureSubpacket.TYPE_KEY_EXPIRATION_TIME
					|| subpackets[x].getType()
						== SignatureSubpacket.TYPE_SIGNATURE_EXPIRATION_TIME)
				{
					thisSigModified = true;
					sig.removeSubpacket(subpackets[x]);
				}
			}

			if (thisSigModified)
			{

				// remove the signature to modify it.
				signable.removeSignature(sig);

				// put the signature back, resigning.
				signable.sign(
					sig,
					privateKey,
					sig.getSignatureType(),
					sig.getCreationTime(true),
					getRandom());

				modified = true;
			}
		}

		return modified;
	}
	
	public boolean usesSharedSecret(String alias)
		throws IOException, KeyStoreException
	{
		if (alias != null)
			alias = alias.toLowerCase();
		
		//	keyRecords
		KeyRecord publicKey = retrievePublicKeyRecord(alias, null);

		if (publicKey == null)
			return false;
		
		return publicKey.sharedSecret;
	}

	/**
	 * This method updates the random seed stored on the server
	 * with the private key using the current PRNG.
	 */
	public void saveRandomSeed(String alias, byte[] passphrase)
		throws IOException, KeyStoreException, UnrecoverableKeyException
	{
		if ( getRandom() == null ) return;
		getRandom().setSeed(System.currentTimeMillis());
		String randomSeedPackage =
			makeRandomSeed(getPrivateKey(alias, passphrase), getRandom());
		KeyRecord keyRecord = getPrivateKeyRecord(alias);
		if (keyRecord == null)
		{
			Logger.log(this, Logger.WARNING,
					"Cannot save random seed for non-cached private alias");
			return;
		}
		keyserver.savePrivateKeyInformation(keyRecord.privateAlias, null, null,
				randomSeedPackage, null);
		Logger.log(this, Logger.INFO, "Random seed saved");
	}

	/**
	 * Used to feed all available data into the PRNG.  Note that it's
	 * fine to feed private data such as passphrases, private keys, etc.,
	 * because all this data will be unrecoverable.
	 * 
	 * @param input an array of Objects to convert to bytes or strings and
	 *  feed to the PRNG
	 */
	public void updateRandom(Object[] input)
	{
		if (getRandom() == null)
			return;
		getRandom().setSeed(System.currentTimeMillis());
		if (input == null)
			return;
		for (int x = 0; x < input.length; x++)
		{
			if (input[x] == null)
			{
			}
			else if (input[x] instanceof byte[])
			{
				getRandom().setSeed((byte[]) input[x]);
			}
			else if (input[x] instanceof Object[])
			{
				updateRandom((Object[]) input[x]);
			}
			else if (input[x] instanceof Vector)
			{
				Vector v = (Vector) input[x];
				for (int y = 0; y < v.size(); y++)
				{
					updateRandom(new Object[] { v.elementAt(y)});
				}
			}
			else
			{
				getRandom().setSeed(Conversions.stringToByteArray(
						input[x].toString(), UTF8));
			}
		}
	}

	public void setInternalPassword(byte[] password)
		throws IOException, UnrecoverableKeyException, ClassNotFoundException
	{
		this.internalPassword = password;
		if (encryptedKeyRecords != null)
		{
			keyRecords = (Hashtable) ObjectEncryption.passwordDecryptObject(
					encryptedKeyRecords, password);
			encryptedKeyRecords = null;
			Logger.log(this, Logger.DEBUG, "Private key records decrypted");
		}
	
		if (encryptedCachedPasswords != null)
		{
			cachedPasswords = (Vector)ObjectEncryption.passwordDecryptObject(
					encryptedCachedPasswords, password);
			encryptedCachedPasswords = null;
			Logger.log(this, Logger.DEBUG,
					"Cached passwords decrypted");
		}
	}
	
	public void setNewEncryptionKeyAlgorithm(String newEncryptionKeyAlgorithm)
	{
		this.newEncryptionKeyAlgorithm = 
			AlgorithmFactory.getPublicKeyCipherID(newEncryptionKeyAlgorithm);
	}

	public void setNewEncryptionKeySize(int newEncryptionKeySize)
	{
		this.newEncryptionKeySize = newEncryptionKeySize;
	}

	public void setNewSigningKeyAlgorithm(String newSigningKeyAlgorithm)
	{
		this.newSigningKeyAlgorithm =
			AlgorithmFactory.getPublicKeyCipherID(newSigningKeyAlgorithm);
	}

	public void setNewSigningKeySize(int newSigningKeySize)
	{
		this.newSigningKeySize = newSigningKeySize;
	}

	public void setNewKeySignatureHashAlgorithm(String newKeySignatureHashAlgorithm)
	{
		this.newKeySignatureHashAlgorithm =
			AlgorithmFactory.getHashID(newKeySignatureHashAlgorithm);
	}

	public void setNewPrivateAliasHashAlgorithm(String newPrivateAliasHashAlgorithm)
	{
		this.newPrivateAliasHashAlgorithm =
			AlgorithmFactory.getHashID(newPrivateAliasHashAlgorithm);
	}

	public void setNewPrivateAliasIterationCount(int newPrivateAliasIterationCount)
	{
		this.newPrivateAliasIterationCount = newPrivateAliasIterationCount;
	}

	public void setNewKeySymmetricAlgorithm(String newKeySymmetricAlgorithm)
	{
		this.newKeySymmetricAlgorithm =
			AlgorithmFactory.getSymmetricCipherID(newKeySymmetricAlgorithm);
	}
	
	public Key getCaCertificate()
	{
		if ( caCertificate == null )
			return _getStaticCaCertificate();
		return caCertificate;
	}
	
	public void setCaCertificate(Key key)
	{
		this.caCertificate = key;
	}
	
	private void writeObject(java.io.ObjectOutputStream out)
			throws IOException, UnrecoverableKeyException
	{
		if (internalPassword != null)
		{
			if (keyRecords != null && keyRecords.size() > 0)
			{
				encryptedKeyRecords = ObjectEncryption.passwordEncryptObject(
						keyRecords, internalPassword, getRandom());
				Logger.log(this, Logger.DEBUG,
						"Key records encrypted for serialization");
			}
			if (cachedPasswords != null && getCachedPasswordCount() > 0)
			{
				encryptedCachedPasswords = ObjectEncryption
						.passwordEncryptObject(cachedPasswords,
								internalPassword, getRandom());
				Logger.log(this, Logger.DEBUG,
						"Cached passwords encrypted for serialization");
			}
		}
		out.defaultWriteObject();
	}

	private KeyRecord getPrivateKeyRecord(String alias)
	{
		if ( keyRecords == null ) return null;
		return (KeyRecord)keyRecords.get(alias);
	}
	
	private void setPrivateKeyRecord(String alias, KeyRecord keyRecord)
	{
		if ( keyRecords == null ) keyRecords = new Hashtable();
		keyRecords.put(alias, keyRecord);
	}
	
	private void removePrivateKeyRecord(String alias)
	{
		keyRecords.remove(alias);
	}
	
	private KeyGenerator createKeyGenerator()
	{
		KeyGenerator generator = new KeyGenerator(new SecureRandom());
		generator.setEncryptionKeyAlgorithm(newEncryptionKeyAlgorithm);
		generator.setEncryptionKeySize(newEncryptionKeySize);
		generator.setSigningKeyAlgorithm(newSigningKeyAlgorithm);
		generator.setSigningKeySize(newSigningKeySize);
		generator.setHashAlgorithm(newKeySignatureHashAlgorithm);
		
		generator.addDesignatedRevoker(
			getCaCertificate().getFingerprint(),
			CIPHER_DSA,
			false);

		generator.addPreferredHashAlgorithm(HASH_SHA256);
		generator.addPreferredHashAlgorithm(HASH_SHA384);
		generator.addPreferredHashAlgorithm(HASH_SHA512);
		generator.addPreferredHashAlgorithm(HASH_RIPEMD160);
		generator.addPreferredHashAlgorithm(HASH_SHA1);
		generator.addPreferredSymmetricAlgorithm(CIPHER_AES256);
		generator.addPreferredSymmetricAlgorithm(CIPHER_AES192);
		generator.addPreferredSymmetricAlgorithm(CIPHER_AES128);
		generator.addPreferredSymmetricAlgorithm(CIPHER_TWOFISH);
		generator.addPreferredSymmetricAlgorithm(CIPHER_BLOWFISH);
		
		return generator;
	}
	
	/**
	 * Generates a new key pair and appends it to the existing keys for the user
	 * @param alias
	 * @param passphrase
	 * @throws KeyStoreException
	 * @throws IOException
	 */
	public void generateAndAddNewKey(String alias, byte[] passphrase) throws KeyStoreException, IOException
	{		
		generateAndAddNewKey(alias, passphrase, null);
	}
	
	/**
	 * Generates a new key pair and appends it to the existing keys for the user
	 * @param alias
	 * @param passphrase
	 * @param privateKeyRecord
	 * @param publicKeyRecord
	 * @throws KeyStoreException
	 * @throws IOException
	 */
	public void generateAndAddNewKey(String alias, byte[] passphrase, 
			KeyRecord privateKeyRecord) throws KeyStoreException, IOException
	{		
		if (privateKeyRecord == null) {
			privateKeyRecord = retrievePrivateKeyRecord(alias, passphrase);
		}
				
		String privateAlias = privateKeyRecord.privateAlias;
		// make sure we have a passphrase otherwise this will not work
		LineInterpolation.validateSecret(passphrase);
		// Create the key generator
		KeyGenerator generator = createKeyGenerator();

		Key key =
			generator.generateKey("\"" + privateKeyRecord.alias + "\" <" + privateKeyRecord.alias + ">", null);
		
		Keyring privateKeyring = new Keyring();
						
		privateKeyring.addKey(key);
		
		Keyring publicKeyring = new Keyring();
		publicKeyring.addKey(key);

		try
		{
			Key[] keys = publicKeyring.getKeys(alias);
			if (keys == null || keys.length == 0) {
				throw new RuntimeException("Should never happen");
			}
			Conversions.bytesToHexString((keys[keys.length - 1]).getKeyID());
		}
		catch (MissingSelfSignatureException e)
		{
			throw ExceptionWrapper.wrapInRuntimeException("Should never happen", e);
		}
		catch (InvalidSignatureException e)
		{
			throw ExceptionWrapper.wrapInRuntimeException("Should never happen", e);
		}
		
		// Save the new Private Key
		PrivateKey privateKeyObj = new com.hush.hee.keyserver.PrivateKey();
		privateKeyObj.setEncryptedPrivateKey(EncryptedPrivateKeyPackage
				.makePrivateKeyPackage(privateKeyring, passphrase,
						getRandom(), newKeySymmetricAlgorithm,
						newPrivateAliasHashAlgorithm,
						newPrivateAliasIterationCount));
		privateKeyObj.setIsMainKey(Boolean.TRUE);
		
		keyserver.savePrivateKeyInformation(privateAlias, null, 
				new PrivateKey[] { privateKeyObj }, null, Boolean.TRUE);
		
		removePrivateKeyRecord(alias);
		
		retrievePrivateKeyRecord(alias, passphrase);
			
		// Save the new public key
		PublicKey publicKeyObj = new PublicKey();		
		publicKeyObj.setKeyID(Conversions
				.bytesToHexString(key.getKeyID()));
		publicKeyObj.setKey(publicKeyring.toString());
		keyserver.savePublicKeyInformation(alias, 
				new PublicKey[]{ publicKeyObj }, null, 
				null, null, null, null, null);
	}

	public void setEnableRSAKeyUpgrade(boolean enableRSAKeyUpgrade)
	{
		this.enableRSAKeyUpgrade = enableRSAKeyUpgrade;
	}
}