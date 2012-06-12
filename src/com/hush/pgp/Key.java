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
import java.io.Serializable;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.ElGamalEngine;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.DSAKeyPairGenerator;
import org.bouncycastle.crypto.generators.ElGamalKeyPairGenerator;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.DESedeParameters;
import org.bouncycastle.crypto.params.DSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.params.ElGamalKeyGenerationParameters;
import org.bouncycastle.crypto.params.ElGamalParameters;
import org.bouncycastle.crypto.params.ElGamalPrivateKeyParameters;
import org.bouncycastle.crypto.params.ElGamalPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.signers.DSASigner;

import com.hush.util.ArrayTools;
import com.hush.util.Conversions;
import com.hush.util.ExceptionWrapper;
import com.hush.util.Logger;
import com.hush.util.UnrecoverableKeyException;

/**
 * An object representing a PGP key.  This it may be either a
 * public key or a secret key.  The only difference is that a
 * public key will contain no secret key material.
 *
 * @author Brian Smith
 *
 */
public class Key extends Signable implements Serializable
{
	private static final long serialVersionUID = 6439913155839714018L;
	
	/**
	 * Enum like class used to describe the key type
	 * @author sean
	 *
	 */
	public static class KeyType
	{
		public static final KeyType ENCRYPTION = new KeyType(KeyFlags.ENCRYPT_COMMUNICATIONS + KeyFlags.ENCRYPT_STORAGE); 
		public static final KeyType SIGNING = new KeyType(KeyFlags.SIGN_DATA);
		public static final KeyType BOTH = new KeyType(KeyFlags.ENCRYPT_COMMUNICATIONS + KeyFlags.ENCRYPT_STORAGE + KeyFlags.SIGN_DATA);
		
		private final byte keyFlags;
		
		private KeyType(int keyFlags) {
			this.keyFlags = (byte) keyFlags;
		}

		public KeyFlags getKeyFlags() 
		{			
			return new KeyFlags(new byte[] {this.keyFlags});
		}
	};

	public static final BigInteger ONE = new BigInteger("1");
	
	/**
	 * Constant for secret key encryption.  (RFC2440 5.5.3)
	 */
	public static final int ENCRYPTED_WITH_MOD65536_CHECKSUM = 255;

	/**
	 * Constant for secret key encryption.  (RFC2440 5.5.3)
	 */
	public static final int ENCRYPTED_WITH_SHA1_CHECKSUM = 254;

	/**
	 * Constant for secret key encryption.  (RFC2440 5.5.3)
	 */
	public static final int NOT_ENCRYPTED = 0;

	/**
	 * Default parameters for the DSA algorithm.  (512 bits)
	 */
	public static final DSAParameters DEFAULT_DSA_PARAMETERS_512 =
		new DSAParameters(
			new BigInteger(
				"00ec310f7e8b45d8b751be35ad52cb1aef0327bd424fe5a8116a9b1a26abd61ad6e63a40881ed9c39bdc21097bf5a8c065f44b7087e25201e0dac65ecb1ef5abcd",
				16),
			new BigInteger("00fac7f37ddaa41b7c5a45c1c819244691da5118e7", 16),
			new BigInteger(
				"0bd444bf01520b04218ed795d32b7c683704f9db068aa7a403c554465c7c3bb145d3bc87e51488691e0e50c0c1ed51a40366f5255d2285c48d746a334a6191dc",
				16));

	/**
	 * Default parameters for the DSA algorithm.  (1024 bits)
	 */
	public static final DSAParameters DEFAULT_DSA_PARAMETERS_1024 =
		new DSAParameters(
			new BigInteger(
				"00a64b5d86c488d586484b57f57ee364ba460709594c81b31d1c2102746fac0188a08e0eb8cc5e4a8b8dea0a463f821f764c28da63c90333fe252293ddd81cc2a97d9eed999731fb4f23bc7234d7133cdcde9d00e440fe773b648b23f805070221cea2928538883c31d0646aa66bf63312679a9978a9279b573672d89f18f5a99d",
				16),
			new BigInteger("00c00363965e438fbb6ffc4d5dbc2327d9d0759d05", 16),
			new BigInteger(
				"0090b803f6dd8cbdb78cc74f7da62fe9cf1d5742f04730e9db9465b45e9a28a5c3461b1ecf1a6316b6b2443af959287d03433a0069c23127cde1c4074c8ec48931d854acedc1fc23ae279d0d1e26e4438b1b77c87a8fbcf410ef8c8d114cbb025e809f989049919cc7bd7627ff6dc08eea2898f0f9e1a6e3a7d873580e49b7601a",
				16));

	/**
	 * Default parameters for the ElGamal algorithm.  (2048 bits)
	 */
	public static final ElGamalParameters DEFAULT_ELGAMAL_PARAMETERS_2048 =
		new ElGamalParameters(
			new BigInteger(
				"3108733779506148787754741654571549633492095498013221215"
					+ "1448781444321393445568157959166911302972918628838917381"
					+ "5559396202902449635119970370112539460656789250334558720"
					+ "4372145442621565079845018867532562149818868830260362738"
					+ "8365642425546473761584899398546726625631228589029183157"
					+ "1232652997382418998975601395990771662578142633544327240"
					+ "2038726745659404445849715722603752002156495160166825609"
					+ "1905149808373739011153824316842260356584928931097012930"
					+ "7092797136965880760971465362166396970025024101398911800"
					+ "0223125870554141329386026963120970230581361470158840230"
					+ "2998104362562812340366960005570331931340105075488237470"
					+ "969553357627",
				10),
			new BigInteger("2", 10));

	private int algorithm;
	private long creationTime = 0;
	private byte[] fingerprint = null;
	private byte[] keyID = null;
	private MPI[] publicKey;
	private MPI[] secretKey;
	private byte[] secretKeyMaterial = null;
	private Hashtable subkeys = new Hashtable();
	private Vector trustInfo = new Vector();
	private Vector userAttributes = new Vector();
	private Hashtable userIDs = new Hashtable();
	private long validityPeriod = 0;
	private int version;
	transient private KeyType keyType = null;

	/**
	 * 	Protected constructor.
	 */
	public Key()
	{
	}

	/**
	 * Constructor for generating a new key.
	 * 
	 * @param version must be 4
	 * @param creationTimeSeconds the creation time for the key in seconds since
	 * 1970-01-01 00:00:00 UTC.
	 * @param publicKeyAlgorithm the type of public key to generate
	 * @param keySize the desired key length in bits
	 * @param type the key type and determines its use for example to encrypt data or to sign data
	 * @param random a source of entropy for key generation
	 */
	public Key(
		int version,
		long creationTimeSeconds,
		int publicKeyAlgorithm,
		int keySize,
		KeyType type,
		SecureRandom random)
	{
		if (version != 4)
			throw new IllegalArgumentException("Can only generate version 4 keys");		
		setKeyType(type);
		setVersion(version);
		setCreationTime(creationTimeSeconds);
		setAlgorithm(publicKeyAlgorithm);
		AsymmetricCipherKeyPair keyPair;
		switch (publicKeyAlgorithm)
		{
			case CIPHER_RSA :
			case CIPHER_RSA_SIGN_ONLY :
			case CIPHER_RSA_ENCRYPT_ONLY :
				RSAKeyGenerationParameters params =
					new RSAKeyGenerationParameters(
						DEFAULT_RSA_PUBLIC_EXPONENT,
						random,
						keySize,
						DEFAULT_RSA_PRIME_CERTAINTY);
				RSAKeyPairGenerator keyGen = new RSAKeyPairGenerator();
				keyGen.init(params);
				keyPair = keyGen.generateKeyPair();
				RSAKeyParameters publicKeyParams =
					(RSAKeyParameters) keyPair.getPublic();
				publicKey = new MPI[2];
				publicKey[0] = new MPI(publicKeyParams.getModulus());
				publicKey[1] = new MPI(publicKeyParams.getExponent());
				RSAPrivateCrtKeyParameters privateKeyParams =
					(RSAPrivateCrtKeyParameters) keyPair.getPrivate();
				secretKey = new MPI[4];
				secretKey[0] = new MPI(privateKeyParams.getExponent());
				secretKey[1] = new MPI(privateKeyParams.getP());
				secretKey[2] = new MPI(privateKeyParams.getQ());
				// See notes in the getSecretKey method
				secretKey[3] = new MPI(privateKeyParams.getP()
						.modInverse(privateKeyParams.getQ()));
				break;
			case CIPHER_DSA :
				DSAParameters parameters;
				if ( keySize == 512 )
					parameters = DEFAULT_DSA_PARAMETERS_512;
				else if ( keySize == 1024 )
					parameters = DEFAULT_DSA_PARAMETERS_1024;
				else
					throw new IllegalArgumentException(
							"Only 512 and 1024 bit DSA keys are supported");
				DSAKeyPairGenerator dsaGenerator = new DSAKeyPairGenerator();
				dsaGenerator.init(
					new DSAKeyGenerationParameters(
						random,
						parameters));
				keyPair = dsaGenerator.generateKeyPair();
				DSAPublicKeyParameters dsaPublicKeyParams =
					(DSAPublicKeyParameters) keyPair.getPublic();
				publicKey = new MPI[4];
				publicKey[0] =
					new MPI(dsaPublicKeyParams.getParameters().getP());
				publicKey[1] =
					new MPI(dsaPublicKeyParams.getParameters().getQ());
				publicKey[2] =
					new MPI(dsaPublicKeyParams.getParameters().getG());
				publicKey[3] = new MPI(dsaPublicKeyParams.getY());
				secretKey = new MPI[1];
				secretKey[0] =
					new MPI(
						((DSAPrivateKeyParameters) keyPair.getPrivate())
							.getX());
				break;
			case CIPHER_ELGAMAL :
			case CIPHER_ELGAMAL_ENCRYPT_ONLY :
				if ( keySize != 2048 )
					throw new IllegalArgumentException(
							"Only 2048 bit ElGamal keys are supported");
				ElGamalKeyPairGenerator eGGenerator =
					new ElGamalKeyPairGenerator();
				eGGenerator.init(
					new ElGamalKeyGenerationParameters(
						random,
						DEFAULT_ELGAMAL_PARAMETERS_2048));
				keyPair = eGGenerator.generateKeyPair();
				ElGamalPublicKeyParameters eGPublicKeyParams =
					(ElGamalPublicKeyParameters) keyPair.getPublic();
				publicKey = new MPI[3];
				publicKey[0] =
					new MPI(eGPublicKeyParams.getParameters().getP());
				publicKey[1] =
					new MPI(eGPublicKeyParams.getParameters().getG());
				publicKey[2] = new MPI(eGPublicKeyParams.getY());
				secretKey = new MPI[1];
				secretKey[0] =
					new MPI(
						((ElGamalPrivateKeyParameters) keyPair.getPrivate())
							.getX());
				break;
			default :
				throw new IllegalArgumentException(
					"Unsupported algorithm: " + publicKeyAlgorithm);
		}
		test(random);
	}

	/**
	 * Adds a subkey to the key.  If a key with the same key ID already
	 * exists, the information is merged.
	 *
	 * @param subkey the subkey to add
	 * @return either the sub key, or the sub key with which it was
	 * merged
	 */
	public Key addSubkey(Key subkey)
	{
		subkey.setMainKey(this);
		String keyID = Conversions.bytesToHexString(subkey.getKeyID());
		Object existingKeyObj = subkeys.get(keyID);
		if (existingKeyObj == null)
		{
			subkeys.put(keyID, subkey);
			return subkey;
		}
		else
		{
			Key existingKey = (Key) existingKeyObj;
			existingKey.merge(subkey);
			return existingKey;
		}
	}

	/**
	 * Adds trust into to the key.  Application specific.
	 * 
	 * @param trustInformation the trust information to add
	 */
	public void addTrustInformation(byte[] trustInformation)
	{
		trustInfo.addElement(trustInformation);
	}

	/**
	 * Adds a user attribute to the key.
	 * 
	 * @param userAttribute the user attribute to add
	 */
	public void addUserAttribute(UserAttribute userAttribute)
	{
		userAttribute.setMainKey(this);
		userAttributes.addElement(userAttribute);
	}

	/**
	 * Adds a user ID to the key.  If a user ID with the same identifying
	 * string already exists, the information is merged.
	 * 
	 * @param userID the user ID to add
	 * @return either the user ID, or the user ID with which it was
	 * merged
	 */
	public UserID addUserID(UserID userID)
	{
		userID.setMainKey(this);
		Object existingUserIDObj = userIDs.get(userID.toString());
		if (existingUserIDObj == null)
		{
			userIDs.put(userID.toString(), userID);
			return userID;
		}
		Signature[] newSigs = userID.getSignatures(-1, null);
		UserID existingUserID = (UserID) existingUserIDObj;
		for (int x = 0; x < newSigs.length; x++)
		{
			existingUserID.addSignature(newSigs[x]);
		}
		return existingUserID;
	}

	private CipherParameters createSymmetricCipherParameters(
		byte[] key,
		byte[] iv,
		int symmetricAlgorithm)
	{
		KeyParameter keyParam;
		if (symmetricAlgorithm == CIPHER_3DES)
			keyParam = new DESedeParameters(key);
		else
			keyParam = new KeyParameter(key);
		return new ParametersWithIV(keyParam, iv);
	}

	/**
	 * Decrypts any secret key material associated with the key so
	 * that the secret key can be used for signing or decryption.
	 * 
	 * @param password the password that will decrypt the key.
	 */
	public void decryptSecretKey(byte[] password)
		throws DataFormatException, UnrecoverableKeyException
	{
		try
		{
			if (secretKeyMaterial == null)
				throw new UnrecoverableKeyException("No secret key material to decrypt");

			ByteArrayInputStream keyMaterialStream =
				new ByteArrayInputStream(secretKeyMaterial);

			int usageConvention = keyMaterialStream.read();

			Logger.log(
				this,
				Logger.DEBUG,
				"Secret key usage convention: " + usageConvention);

			if (usageConvention == -1)
				throw new DataFormatException("Unexpected end of data while reading usage convention");

			byte[] mpiBytes = null;
			byte[] checksumBytes = null;

			if (usageConvention == NOT_ENCRYPTED)
			{
				mpiBytes = new byte[secretKeyMaterial.length - 3];
				checksumBytes = new byte[2];
				System.arraycopy(
					secretKeyMaterial,
					1,
					mpiBytes,
					0,
					secretKeyMaterial.length - 3);
				System.arraycopy(
					secretKeyMaterial,
					secretKeyMaterial.length - 2,
					checksumBytes,
					0,
					2);
			}
			else if (password == null)
			{
				throw new UnrecoverableKeyException("Secret key material is password encrypted");
			}
			else
			{
				// Secret key material is encrypted
				int symmetricAlgorithm = -1;
				S2kAlgorithm s2k = null;

				if (usageConvention == ENCRYPTED_WITH_SHA1_CHECKSUM
					|| usageConvention == ENCRYPTED_WITH_MOD65536_CHECKSUM)
				{
					// Secret key material encrypted with S2K specifier

					symmetricAlgorithm = keyMaterialStream.read();
					if (symmetricAlgorithm == -1)
						throw new DataFormatException("Unexpected end of data while reading symmetric algorithm");
					// Read the s2k specifier
					s2k = new S2kAlgorithm(keyMaterialStream);
				}

				if (symmetricAlgorithm == -1)
				{
					// We don't have a symmetric algorithm yet, so it is
					// specified by the usage convention octet.
					symmetricAlgorithm = usageConvention;
				}

				Logger.log(
					this,
					Logger.DEBUG,
					"Symmetric algorithm: " + symmetricAlgorithm);

				BufferedBlockCipher cipher =
					AlgorithmFactory.getStandardCFBBlockCipher(
						symmetricAlgorithm);

				byte[] iv = new byte[cipher.getBlockSize()];

				if (keyMaterialStream.read(iv) != iv.length)
					throw new DataFormatException("Unexpected end of data while reading IV");
				byte[] symmetricKey;
				if (s2k != null)
				{
					// Generate the key by S2K conversion

					symmetricKey =
						s2k.s2k(
							password,
							SYMMETRIC_CIPHER_KEY_LENGTHS[symmetricAlgorithm]);
				}
				else
				{
					// Use a simple MD5 hash to convert the password to a key

					Digest digest = AlgorithmFactory.getDigest(HASH_MD5);
					digest.update(password, 0, password.length);
					symmetricKey =
						new byte[SYMMETRIC_CIPHER_KEY_LENGTHS[symmetricAlgorithm]];
					digest.doFinal(symmetricKey, 0);
				}

				CipherParameters parameters =
					createSymmetricCipherParameters(
						symmetricKey,
						iv,
						symmetricAlgorithm);

				byte[] remainingBytes = getRemainingBytes(keyMaterialStream);

				byte[] decryptedBytes;

				if (version >= 4)
					decryptedBytes =
						decryptVersion4(remainingBytes, cipher, parameters);
				else
					decryptedBytes =
						decryptVersion3(remainingBytes, cipher, parameters);

				if (usageConvention == ENCRYPTED_WITH_SHA1_CHECKSUM)
				{
					// Use a SHA1 hash for the checksum
					mpiBytes =
						new byte[decryptedBytes.length
							- HASH_LENGTHS[HASH_SHA1]];
					checksumBytes = new byte[HASH_LENGTHS[HASH_SHA1]];
				}
				else if (
					usageConvention == ENCRYPTED_WITH_MOD65536_CHECKSUM
						|| version < 4)
				{
					// Use sum mod 65536 for the checksum
					mpiBytes = new byte[decryptedBytes.length - 2];
					checksumBytes = new byte[2];
				}
				else
				{
					mpiBytes = decryptedBytes;
				}

				if (checksumBytes != null)
				{
					System.arraycopy(
						decryptedBytes,
						0,
						mpiBytes,
						0,
						mpiBytes.length);
					System.arraycopy(
						decryptedBytes,
						mpiBytes.length,
						checksumBytes,
						0,
						checksumBytes.length);
				}

				// Wipe the key that encrypted the MPIs
				ArrayTools.wipe(symmetricKey);
			}

			Logger.hexlog(
				this,
				Logger.VERBOSE,
				"Raw secret key MPI's: ",
				mpiBytes);

			MPI[] mpis = MPI.parseAllMPIs(mpiBytes, 0, mpiBytes.length);

			if (checksumBytes != null)
			{
				byte[] calculatedChecksum;

				if (usageConvention == 254)
					calculatedChecksum = PgpUtils.checksumSha1(mpiBytes);
				else
					calculatedChecksum = PgpUtils.checksumMod65536(mpiBytes);

				Logger.hexlog(
					this,
					Logger.DEBUG,
					"Stored checksum: ",
					checksumBytes);
				Logger.hexlog(
					this,
					Logger.DEBUG,
					"Calculated checksum: ",
					calculatedChecksum);

				// TODO: The checksum fails for Version 3 keys.
				if (!ArrayTools.equals(checksumBytes, calculatedChecksum))
					throw new DataFormatException("Invalid password or corrupt data");
			}

			// Wipe as much of the sensitive information as we can
			ArrayTools.wipe(mpiBytes);

			setSecretKey(mpis);
		}
		catch (IOException e)
		{
			throw DataFormatException.wrap(
					"Unexpected error decrypting secret key material", e);
		}

		// Decrypt all the subkeys
		Key[] subkeys = getSubkeys();
		for (int x = 0; x < subkeys.length; x++)
			subkeys[x].decryptSecretKey(password);
	}

	private byte[] decryptVersion3(
		byte[] b,
		BufferedBlockCipher cipher,
		CipherParameters params)
		throws IOException
	{

		byte[] returnValue = new byte[b.length];
		int offset = 0;

		// The MPI's span all but the last two bytes, which are the checksum
		MPI[] mpis = MPI.parseAllMPIs(b, 0, b.length - 2);
		byte[] mpiRawBytes;
		for (int x = 0; x < mpis.length; x++)
		{
			System.arraycopy(b, offset, returnValue, offset, 2);
			offset += 2;

			cipher.init(false, params);
			mpiRawBytes = mpis[x].getRaw();

			int n =
				cipher.processBytes(
					mpiRawBytes,
					2,
					mpiRawBytes.length - 2,
					mpiRawBytes,
					2);
			try
			{
				cipher.doFinal(mpiRawBytes, n + 2);
			}
			catch (InvalidCipherTextException e)
			{
				throw UnrecoverableKeyException
						.wrap(
								"Unexpected invalid cipher text although password was correct",
								e);
			}

			System.arraycopy(
				mpiRawBytes,
				2,
				returnValue,
				offset,
				mpiRawBytes.length - 2);

			offset += mpiRawBytes.length - 2;
		}

		System.arraycopy(
			b,
			b.length - 2,
			returnValue,
			returnValue.length - 2,
			2);
		return returnValue;
	}

	private byte[] decryptVersion4(
		byte[] b,
		BufferedBlockCipher cipher,
		CipherParameters parameters)
		throws IOException
	{
		cipher.init(false, parameters);
		byte[] decryptedBytes = new byte[b.length];
		int n = cipher.processBytes(b, 0, b.length, decryptedBytes, 0);
		try
		{
			cipher.doFinal(decryptedBytes, n);
		}
		catch (InvalidCipherTextException e)
		{
			throw ExceptionWrapper
			.wrapInIOException(
					"Unexpected invalid cipher text although password was correct",
					e);
		}
		return decryptedBytes;
	}

	/**
	 * This method encrypts any existing secret key material with the password given.
	 * If the password is null, the secret key material will be left unencrypted.
	 * This method can be used to change or eliminate a password on an existing key.
	 * 
	 * @param password the password or null for no password
	 * @param symmetricAlgorithm the algorithm to use for encryption, a constant from 
	 * <code>com.hush.pgp.PgpConstants</code>
	 * @param s2kType the type of S2K conversion to use, a constant from
	 * <code>com.hush.pgp.PgpConstants</code>
	 * @param s2kHashAlgorithm the hash algorithm with which to process
	 * the password, a constant from <code>com.hush.pgp.PgpConstants</code>
	 * @param s2kCount the number of octets to process while converting
	 * the password
	 * @param checksumMod65536 if true, use MOD 65536 for the checksum on
	 * encrypted keys; uses SHA1 otherwise; does not apply to non-encrypted;
	 * setting to true will give PGP &gt;= 6.5.8 compatibility.
	 */
	public void encryptSecretKeyMaterial(
		byte[] password,
		int symmetricAlgorithm,
		int s2kType,
		int s2kHashAlgorithm,
		int s2kCount,
		boolean checksumMod65536)
		throws UnrecoverableKeyException
	{
		if (getVersion() < 4)
			throw new IllegalStateException(
				"Encryption of secret key material is "
					+ "not supported for versions below 4");
		if (secretKey == null)
			throw new UnrecoverableKeyException("No secret key available");
		try
		{
			ByteArrayOutputStream encryptedKeyMaterialStream =
				new ByteArrayOutputStream();
			if (password == null || password.length == 0)
			{
				encryptedKeyMaterialStream.write(NOT_ENCRYPTED);
				byte[] mpiBytes = MPI.mpis2Bytes(secretKey);
				encryptedKeyMaterialStream.write(mpiBytes);
				encryptedKeyMaterialStream.write(
					PgpUtils.checksumMod65536(mpiBytes));
			}
			else
			{
				if (checksumMod65536)
				{
					encryptedKeyMaterialStream.write(
						ENCRYPTED_WITH_MOD65536_CHECKSUM);
				}
				else
				{
					encryptedKeyMaterialStream.write(
						ENCRYPTED_WITH_SHA1_CHECKSUM);
				}
				encryptedKeyMaterialStream.write(symmetricAlgorithm);
				byte[] s2kSalt = new byte[8];
				new SecureRandom().nextBytes(s2kSalt);
				S2kAlgorithm s2k =
					new S2kAlgorithm(
						s2kType,
						s2kHashAlgorithm,
						s2kSalt,
						s2kCount);
				encryptedKeyMaterialStream.write(s2k.getBytes());
				byte[] symmetricKey =
					s2k.s2k(
						password,
						SYMMETRIC_CIPHER_KEY_LENGTHS[symmetricAlgorithm]);
				BufferedBlockCipher cipher =
					AlgorithmFactory.getStandardCFBBlockCipher(
						symmetricAlgorithm);
				byte[] iv = new byte[cipher.getBlockSize()];
				new SecureRandom().nextBytes(iv);
				encryptedKeyMaterialStream.write(iv);
				CipherParameters parameters =
					createSymmetricCipherParameters(
						symmetricKey,
						iv,
						symmetricAlgorithm);
				cipher.init(true, parameters);
				byte[] plaintextBytes = MPI.mpis2Bytes(secretKey);
				byte[] checksum;
				if (checksumMod65536)
					checksum = PgpUtils.checksumMod65536(plaintextBytes);
				else
					checksum = PgpUtils.checksumSha1(plaintextBytes);
				byte[] encryptedBytes =
					new byte[plaintextBytes.length + checksum.length];
				int n =
					cipher.processBytes(
						plaintextBytes,
						0,
						plaintextBytes.length,
						encryptedBytes,
						0);
				n
					+= cipher.processBytes(
						checksum,
						0,
						checksum.length,
						encryptedBytes,
						n);
				try
				{
					cipher.doFinal(encryptedBytes, n);
				}
				catch (InvalidCipherTextException e)
				{
					throw ExceptionWrapper.wrapInRuntimeException("Should never happen", e);
				}
				encryptedKeyMaterialStream.write(encryptedBytes);
			}

			setSecretKeyMaterial(encryptedKeyMaterialStream.toByteArray());
		}
		catch (IOException e)
		{
		}

		// Encrypt all the subkeys
		Key[] subkeys = getSubkeys();
		for (int x = 0; x < subkeys.length; x++)
			subkeys[x].encryptSecretKeyMaterial(
				password,
				symmetricAlgorithm,
				s2kType,
				s2kHashAlgorithm,
				s2kCount,
				checksumMod65536);
	}

	/**
	 * Returns the public key algorithm.
	 */
	public int getAlgorithm()
	{
		return algorithm;
	}

	/**
	 * Returns the key as an old format public key packet.
	 * Useful for signature verification.
	 */
	public byte[] getBytesForSignature(int signatureVersion)
	{
		// Note: the signature version has no impact in this case.

		ByteArrayOutputStream publicKeyMaterialStream =
			new ByteArrayOutputStream();
		try
		{
			int x;
			for (x = 0; x < publicKey.length; x++)
			{
				publicKeyMaterialStream.write(publicKey[x].getRaw());
			}
		}
		catch (IOException e)
		{
			//Will never happen
		}
		byte[] publicKeyMaterialBytes = publicKeyMaterialStream.toByteArray();
		byte[] publicKeyPacket;
		if (getVersion() >= 4)
			publicKeyPacket = new byte[9 + publicKeyMaterialBytes.length];
		else
			publicKeyPacket = new byte[11 + publicKeyMaterialBytes.length];

		publicKeyPacket[0] = (byte) 0x99;

		Conversions.longToBytes(
			publicKeyPacket.length - 3,
			publicKeyPacket,
			1,
			2);

		publicKeyPacket[3] = (byte) getVersion();

		int placeHolder = 4;

		Conversions.longToBytes(
			getCreationTime(),
			publicKeyPacket,
			placeHolder,
			4);

		placeHolder += 4;

		if (getVersion() < 4)
		{
			Conversions.longToBytes(
				getKeyExpirationTime() / 86400,
				publicKeyPacket,
				placeHolder,
				2);
			placeHolder += 2;
		}

		publicKeyPacket[placeHolder] = (byte) getAlgorithm();

		placeHolder++;

		Logger.hexlog(
			this,
			Logger.DEBUG,
			"Public key bytes for signing: ",
			publicKeyPacket);

		System.arraycopy(
			publicKeyMaterialBytes,
			0,
			publicKeyPacket,
			placeHolder,
			publicKeyMaterialBytes.length);

		Logger.hexlog(
			this,
			Logger.DEBUG,
			"Public key bytes for signing: ",
			publicKeyPacket);

		return publicKeyPacket;
	}

	/**
	 * Returns the creation time in seconds since midnight, 1 January 1970 UTC.
	 */
	public long getCreationTime()
	{
		return creationTime;
	}

	/**
	 * Finds the most recent, valid, non-revoked encryption key
	 * and returns it, or null if one is not found.  Subkeys are preferred
	 * over main keys.
	 * <p>
	 * If you want to use a key for encryption that is revoked or no longer
	 * valid, select it manually, not using this method.
	 * <p>
	 * This goes only by the algorithm type, not by the usage convention signature
	 * packet which may or may not exist.
	 * <p>
	 * This will not return keys for experimental algorithms such as Elliptic
	 * Curve or X9.42.
	 * <p>
	 * This will not verify any signatures.  Those have to be checked separately.
	 * All self-signatures were probabaly verified when you retrieved the key from
	 * its key ring.
	 * 
	 * @return the encryption key
	 */
	public Key getEncryptionKey()
	{
		Key returnValue = null;
		Key[] subkeys = getSubkeys();
		Key thisKey;
		for (int x = 0; x < subkeys.length; x++)
		{
			thisKey = subkeys[x].getEncryptionKey();
			if (returnValue == null
				|| thisKey.getCreationTime() > returnValue.getCreationTime())
				returnValue = thisKey;
		}
		if ( returnValue == null && isEncryptionKey()
				&& !isExpired(System.currentTimeMillis() / 1000)
				&& !isRevoked())
			{
				return this;
			}
		return returnValue;
	}
	
	public Key[] getAllEncryptionKeys()
	{
		Vector v = new Vector();
		getAllEncryptionKeys(this, v);
		Key[] keys = new Key[v.size()];
		v.copyInto(keys);
		return keys;
	}
	
	private static void getAllEncryptionKeys(Key thisKey, Vector encryptionKeys)
	{
		if ( thisKey.isEncryptionKey() )
			encryptionKeys.addElement(thisKey);
		Key[] subkeys = thisKey.getSubkeys();
		for( int x=0; x<subkeys.length; x++)
		{
			getAllEncryptionKeys(subkeys[x], encryptionKeys);
		}
	}

	/**
	 * Returns the fingerprint.
	 */
	public byte[] getFingerprint()
	{
		if (fingerprint != null)
			return fingerprint;
		Digest fingerprintDigest;
		if (getVersion() == 4)
		{
			fingerprint = new byte[HASH_LENGTHS[HASH_SHA1]];
			fingerprintDigest = AlgorithmFactory.getDigest(HASH_SHA1);
			fingerprint = new byte[HASH_LENGTHS[HASH_SHA1]];
			byte[] toHash = getBytesForSignature(getVersion());
			fingerprintDigest.update(toHash, 0, toHash.length);
		}
		else
		{
			fingerprint = new byte[HASH_LENGTHS[HASH_MD5]];
			fingerprintDigest = AlgorithmFactory.getDigest(HASH_MD5);
			fingerprint = new byte[HASH_LENGTHS[HASH_MD5]];
			throw new RuntimeException("Not completed");
		}
		fingerprintDigest.doFinal(fingerprint, 0);
		return fingerprint;
	}

	/**
	 * Returns the key expiration in seconds since the creation time.
	 * <p>
	 * It returns zero if the key doesn't expire.
	 * 
	 * @return the key expiration time
	 */
	public long getKeyExpirationTime()
	{
		if (getVersion() < 4)
			return validityPeriod;
		Signature[] validitySigs =
			getSignatures(
				(getMainKey() == this)
					? Signature.SIGNATURE_DIRECTLY_ON_KEY
					: Signature.SIGNATURE_SUBKEY_BINDING,
				getMainKey().getKeyID());
		if (validitySigs.length == 0)
			return 0;
		if (validitySigs.length != 1)
			Logger.log(
				this,
				Logger.WARNING,
				"Multiple self-signatures signatures.  Using the first one with an expiration.");
		long keyExpirationTime;
		for (int x = 0; x < validitySigs.length; x++)
		{
			keyExpirationTime = validitySigs[0].getKeyExpirationTime(false);
			if (keyExpirationTime != -1)
				return keyExpirationTime;
		}
		return 0;
	}

	/**
	 * Returns the key ID.
	 */
	public byte[] getKeyID()
	{
		if (keyID != null)
			return keyID;
		keyID = new byte[8];
		if (getVersion() == 4)
		{
			getFingerprint();
			System.arraycopy(fingerprint, 12, keyID, 0, 8);
		}
		else
		{
			RSAKeyParameters keyParams = (RSAKeyParameters) getPublicKey();
			byte[] publicModulusBytes = keyParams.getModulus().toByteArray();
			System.arraycopy(
				publicModulusBytes,
				publicModulusBytes.length - 8,
				keyID,
				0,
				8);
		}

		Logger.hexlog(this, Logger.DEBUG, "Key ID: ", keyID);
		return keyID;
	}

	private byte[] getPreferredAlgorithms(String userID, int type)
	{
		UserID u;
		Signature[] sigs;
		Vector preferredAlgos = new Vector();
		Enumeration userIDList = userIDs.elements();
		for (int x = 0; x < userIDs.size(); x++)
		{

			u = (UserID) userIDList.nextElement();
			if (userID == null || u.hasUserID(userID))
			{
				sigs = u.getSignatures(-1, getKeyID());
				for (int y = 0; y < sigs.length; y++)
				{
					byte[] thesePreferredAlgos;
					switch (type)
					{
						case 0 :
							thesePreferredAlgos =
								sigs[y].getPreferredSymmetricKeyAlgorithms(
									false);
							break;
						case 1 :
							thesePreferredAlgos =
								sigs[y].getPreferredHashAlgorithms(false);
							break;
						case 2 :
							thesePreferredAlgos =
								sigs[y].getPreferredCompressionAlgorithms(
									false);
							break;
						default :
							throw new IllegalArgumentException();
					}
					for (int z = 0;
						thesePreferredAlgos != null
							&& z < thesePreferredAlgos.length;
						z++)
					{
						boolean alreadyThere = false;
						for (int xx = 0;
							alreadyThere == false && xx < preferredAlgos.size();
							xx++)
						{
							if (((Byte) preferredAlgos.elementAt(xx))
								.byteValue()
								== thesePreferredAlgos[z])
								alreadyThere = true;
						}
						if (!alreadyThere)
							preferredAlgos.addElement(
								new Byte(thesePreferredAlgos[z]));
					}
				}
			}
		}
		byte[] preferredAlgoBytes = new byte[preferredAlgos.size()];
		for (int x = 0; x < preferredAlgos.size(); x++)
			preferredAlgoBytes[x] =
				((Byte) preferredAlgos.elementAt(x)).byteValue();

		return preferredAlgoBytes;
	}

	/**
	 * Returns any preferred compression algorithms associated with the
	 * specified user ID, or with any user ID's on the key if userID
	 * is null.
	 */
	public byte[] getPreferredCompressionAlgorithms(String userID)
	{
		return getPreferredAlgorithms(userID, 2);
	}

	/**
	 * Returns any preferred hash algorithms associated with the
	 * specified user ID, or with any user ID's on the key if userID
	 * is null.
	 */
	public byte[] getPreferredHashAlgorithms(String userID)
	{
		return getPreferredAlgorithms(userID, 1);
	}

	/**
	 * Returns any preferred symmetric algorithms associated with the
	 * specified user ID, or with any user ID's on the key if userID
	 * is null.
	 */
	public byte[] getPreferredSymmetricKeyAlgorithms(String userID)
	{
		return getPreferredAlgorithms(userID, 0);
	}

	/**
	 * Returns the public key.
	 */
	public CipherParameters getPublicKey()
	{
		switch (getAlgorithm())
		{
			case CIPHER_RSA :
			case CIPHER_RSA_ENCRYPT_ONLY :
			case CIPHER_RSA_SIGN_ONLY :
				return new RSAKeyParameters(
					false,
					publicKey[0].getBigInteger(),
					publicKey[1].getBigInteger());
			case CIPHER_DSA :
				DSAParameters dsaParams =
					new DSAParameters(
						publicKey[0].getBigInteger(),
						publicKey[1].getBigInteger(),
						publicKey[2].getBigInteger());
				return new DSAPublicKeyParameters(
					publicKey[3].getBigInteger(),
					dsaParams);
			case CIPHER_ELGAMAL :
			case CIPHER_ELGAMAL_ENCRYPT_ONLY :
				ElGamalParameters elgamalParams =
					new ElGamalParameters(
						publicKey[0].getBigInteger(),
						publicKey[1].getBigInteger());
				return new ElGamalPublicKeyParameters(
					publicKey[2].getBigInteger(),
					elgamalParams);
			default :
				throw new IllegalArgumentException(
					"Unsupported algorithm: " + getAlgorithm());
		}
	}

	/**
	 * Returns the public key.
	 */
	public MPI[] getPublicKeyMPIs()
	{
		return publicKey;
	}

	private byte[] getRemainingBytes(InputStream in) throws IOException
	{
		// Read the remaining bytes of the packet into a buffer
		ByteArrayOutputStream remainingBytesStream =
			new ByteArrayOutputStream();
		byte[] b = new byte[512];
		int len;
		while ((len = in.read(b)) != -1)
			remainingBytesStream.write(b, 0, len);
		byte[] remainingBytes = remainingBytesStream.toByteArray();
		return remainingBytes;
	}

	/**
	 * Retrieve the secret key in a form that can be used by the Bouncy Castle crypto
	 * provider.
	 * 
	 * @return the secret key; or null if there is no secret key.
	 */
	public CipherParameters getSecretKey() throws UnrecoverableKeyException
	{
		if (secretKey == null)
		{
			if (secretKeyMaterial == null)
				throw new UnrecoverableKeyException("There is no secret key in this PGP key");
			else
				throw new UnrecoverableKeyException("The secret key has not been decrypted");
		}
		switch (algorithm)
		{
			case CIPHER_RSA :
			case CIPHER_RSA_ENCRYPT_ONLY :
			case CIPHER_RSA_SIGN_ONLY :
				BigInteger d = secretKey[0].getBigInteger();
				BigInteger p = secretKey[1].getBigInteger();
				BigInteger q = secretKey[2].getBigInteger();
				
				// TODO: This is the multiplicative inverse of p, mod q.
				// BouncyCastle wants the multiplicative inverse of q, mod p.
				// There should be some way to use this value, but discard
				// it for now and generate the one needed.
				// - sbs
				BigInteger u = secretKey[3].getBigInteger();
				
				BigInteger qInv = q.modInverse(p);
				BigInteger dP = d.remainder(p.subtract(ONE));
				BigInteger dQ = d.remainder(q.subtract(ONE));
				
				return new RSAPrivateCrtKeyParameters(
						((RSAKeyParameters) getPublicKey()).getModulus(),
						((RSAKeyParameters) getPublicKey()).getExponent(),
						d,
						p,
						q,
						dP,
						dQ,
						qInv
						);
						
			case CIPHER_DSA :
				return new DSAPrivateKeyParameters(
					secretKey[0].getBigInteger(),
					((DSAPublicKeyParameters) getPublicKey()).getParameters());
			case CIPHER_ELGAMAL :
			case CIPHER_ELGAMAL_ENCRYPT_ONLY :
				return new ElGamalPrivateKeyParameters(
					secretKey[0].getBigInteger(),
					((ElGamalPublicKeyParameters) getPublicKey())
						.getParameters());
			default :
				throw new IllegalArgumentException(
					"Unsupported algorithm: " + algorithm);
		}
	}

	/**
	 * Returns the secret key material, which my be encrypted.
	 */
	public byte[] getSecretKeyMaterial()
	{
		return secretKeyMaterial;
	}

	/**
	 * Returns all the subkeys associated with this key.  Note that these
	 * subkeys may not yet have been verified.
	 * 
	 * @return an array of subkeys
	 */
	public Key[] getSubkeys()
	{
		Key[] returnArray = new Key[subkeys.size()];
		Enumeration elements = subkeys.elements();
		for (int x = 0; x < returnArray.length; x++)
			returnArray[x] = (Key) elements.nextElement();
		return returnArray;
	}

	/**
	 * Returns all the trust information associated with this key.
	 * Application specific.
	 * 
	 * @return an array of trust information blocks
	 */
	public byte[][] getTrustInformation()
	{
		byte[][] returnArray = new byte[trustInfo.size()][];
		trustInfo.copyInto(returnArray);
		return returnArray;
	}

	/**
	 * Returns all the user attribute's associated with this key.  Note that these
	 * user attribute's may not yet have been verified.
	 * 
	 * @return an array of user attributes
	 */
	public UserAttribute[] getUserAttributes()
	{
		UserAttribute[] returnArray = new UserAttribute[userAttributes.size()];
		userAttributes.copyInto(returnArray);
		return returnArray;
	}

	/**
	 * Returns all the user ID's associated with this key.  Note that these
	 * user ID's may not yet have been verified.
	 * 
	 * @return an array of user ID's
	 */
	public UserID[] getUserIDs()
	{
		UserID[] returnArray = new UserID[userIDs.size()];
		Enumeration elements = userIDs.elements();
		for (int x = 0; x < returnArray.length; x++)
			returnArray[x] = (UserID) elements.nextElement();
		return returnArray;
	}

	/**
	 * Returns all the user ID's associated with this key that match the given
	 * user ID. Note that these user ID's may not yet have been verified.
	 * 
	 * @return an array of user ID's
	 */
	public UserID[] getUserIDs(String userID)
	{
		Vector returnVector = new Vector();
		Enumeration elements = userIDs.elements();
		while(elements.hasMoreElements())
		{
			UserID thisUserID = (UserID) elements.nextElement();
			if (thisUserID.hasUserID(userID))
			{
				returnVector.addElement(thisUserID);
			}
		}
		UserID[] returnArray = new UserID[returnVector.size()];
		returnVector.copyInto(returnArray);
		return returnArray;
	}

	/**
	 * Returns all the certifications that are signed
	 * by this particular signer and valid for the specified time.
	 * <p>
	 * This method does not check for revocations.
	 * 
	 * @param signer the signer of the certification
	 * @param time check for validity at this time in seconds since
	 * 1970-01-01 00:00:00; 0 to ignore
	 */
	public UserID[] getVerifiedCertifications(Key signer, long time)
		throws InvalidSignatureException
	{
		Vector verified = new Vector();
		Enumeration e = userIDs.elements();
		UserID userID;
		while (e.hasMoreElements())
		{
			userID = (UserID) e.nextElement();
			Signature[] sigs =
				userID.verifySignatures(
					signer,
					Signature.SIGNATURE_CERTIFICATIONS,
					time,
					true);
			if (sigs.length > 0)
				verified.addElement(userID);
		}
		UserID[] returnValue = new UserID[verified.size()];
		verified.copyInto(returnValue);
		return returnValue;
	}

	/**
	 * Returns the version, either 2, 3 or 4.
	 */
	public int getVersion()
	{
		return version;
	}

	/**
	 * Checks to see if this key has a user ID packet that matches
	 * the given user ID.
	 * 
	 * This method does NOT verify that the self signature on the user
	 * ID is valid, so be sure to verify the self-certifications before
	 * you use it.	
	 * 
	 * @param userID
	 * @return true if the user ID is there
	 */
	public boolean hasUserID(String userID)
	{
		Enumeration e = userIDs.elements();
		UserID thisUserID;
		while (e.hasMoreElements())
		{
			thisUserID = (UserID) e.nextElement();
			if (thisUserID.hasUserID(userID))
			{
				return true;
			}
		}
		return false;
	}

	public boolean isEncryptionKey()
	{
		if (getKeyType() == null) {
			// Older key where the algorithm will hopefully determine the key type
			return (getAlgorithm() == CIPHER_RSA
					|| getAlgorithm() == CIPHER_RSA_ENCRYPT_ONLY
					|| getAlgorithm() == CIPHER_ELGAMAL_ENCRYPT_ONLY
					|| getAlgorithm() == CIPHER_ELGAMAL);
		} else {
			return keyType.equals(KeyType.ENCRYPTION) || keyType.equals(KeyType.BOTH);
		}
	}
	
	public boolean isSigningKey()
	{
		if (getKeyType() == null) {
			// Older key where the algorithm will hopefully determine the key type
			return !isEncryptionKey();
		} else {
			return keyType.equals(KeyType.SIGNING) || keyType.equals(KeyType.BOTH);
		}
	}
	
	/**
	 * Checks to see if this key is expired.  If this key's main key is considered
	 * to be expired, this key is considered to be expired as well.  This method does
	 * not verify any signatures.
	 * 
	 * @param time check for validity at this time in seconds since 1970-01-01 00:00:00
	 */
	public boolean isExpired(long time)
	{
		long keyExpirationTime = getKeyExpirationTime();
		if (getMainKey() != this && getMainKey().isExpired(time))
			return true;
		return (
			keyExpirationTime != 0
				&& getCreationTime() + keyExpirationTime <= time);
	}

	/**
	 * Removes the first (and only) instance of a subkey from the key.
	 * 
	 * @return true if a subkey was found and removed.
	 */
	public boolean removeSubkey(Key subkey)
	{
		return removeFirstMatchFromHashtable(subkey, subkeys);
	}

	/**
	 * Removes all instances of the particular user attribute from
	 * the key.
	 * 
	 * @return true if at least one user attribute was found and removed.
	 */
	public boolean removeUserAttribute(UserAttribute userAttribute)
	{
		boolean removed = false;
		while (userAttributes.removeElement(userAttribute))
		{
			removed = true;
		}
		return removed;
	}

	/**
	 * Removes the first (and only) instance of a user ID from the key.
	 * 
	 * @return true if a user ID was found and removed.
	 */
	public boolean removeUserID(UserID userID)
	{
		return removeFirstMatchFromHashtable(userID, userIDs);
	}

	private boolean removeFirstMatchFromHashtable(Object o, Hashtable h)
	{
		Enumeration e = h.keys();
		while (e.hasMoreElements())
		{
			Object thisKey = e.nextElement();
			if (h.get(thisKey) == o)
			{
				return h.remove(thisKey) != null;
			}
		}
		return false;
	}

	public void setAlgorithm(int algorithm)
	{
		this.algorithm = algorithm;
	}

	public void setCreationTime(long creationTime)
	{
		this.creationTime = creationTime;
	}

	public void setKeyID(byte[] keyID)
	{
		this.keyID = keyID;
	}

	public void setPublicKey(MPI[] publicKey)
	{
		this.publicKey = publicKey;
	}

	public void setSecretKey(MPI[] secretKey)
	{
		this.secretKey = secretKey;
	}

	public void setSecretKeyMaterial(byte[] secretKeyMaterial)
	{
		this.secretKeyMaterial = secretKeyMaterial;
		// Just in case there is no password on the secretKeyMaterial,
		// try decrypting it.
		try
		{
			decryptSecretKey(null);
		}
		catch (Exception e)
		{
		}
	}

	/**
	 * Sets the signatures.
	 * 
	 * @param signatures the signatures to set
	 */
	public void setSignatures(Vector signatures)
	{
		this.signatures = signatures;
	}

	/**
	 * Sets the validity period for the key.  Only applicable to
	 * version 3 or lower keys.
	 * 
	 * @param validityPeriod the validity period in seconds
	 */
	public void setValidityPeriod(long validityPeriod)
	{
		this.validityPeriod = validityPeriod;
	}

	/**
	 * Sets the version on the key.
	 * 
	 * @param version the version (either 3 or 4)
	 */
	public void setVersion(int version)
	{
		this.version = version;
	}

	/**
	 * This method verifies the self-signature this key, and all
	 * subkeys and user IDs.
	 * <p>
	 * If this method is called on a subkey, it just passes the
	 * method up to the parent key.
	 * <p>
	 * This method does NOT check to see if any keys or 
	 * certifications have expired.
	 * <p>
	 * This method does NOT check to see if any keys or
	 * certifications have been revoked.
	 * <p>
	 * @throws MissingSelfSignatureException if there are any unsigned subkeys or
	 * user ID's; or if a signature fails.
	 */
	public void verifySelfSignatures()
		throws MissingSelfSignatureException, InvalidSignatureException
	{
		if (getMainKey() != this)
		{
			getMainKey().verifySelfSignatures();
			return;
		}

		// Verify any self-signatures directly on the key
		verifySignatures(
			this,
			new int[] { Signature.SIGNATURE_DIRECTLY_ON_KEY },
			0,
			true);

		Enumeration e;

		// Verify any self-certifications
		e = userIDs.elements();
		UserID userID;
		while (e.hasMoreElements())
		{
			userID = (UserID) e.nextElement();
			Signature[] sigs =
				userID.verifySignatures(
					this,
					Signature.SIGNATURE_CERTIFICATIONS,
					0,
					true);
			if (sigs.length == 0)
				throw new MissingSelfSignatureException(
					"No signature on user ID "
						+ userID.toString()
						+ " by key "
						+ Conversions.bytesToHexString(getKeyID()));
		}

		e = userAttributes.elements();
		UserAttribute userAttribute;
		while (e.hasMoreElements())
		{
			userAttribute = (UserAttribute) e.nextElement();
			Signature[] sigs =
				userAttribute.verifySignatures(
					this,
					Signature.SIGNATURE_CERTIFICATIONS,
					0,
					true);
			if (sigs.length == 0)
				throw new MissingSelfSignatureException(
					"No signature on user attribute "
						+ " by key "
						+ Conversions.bytesToHexString(getKeyID()));
		}

		// Verify any subkeys
		e = subkeys.elements();
		Key subkey;
		while (e.hasMoreElements())
		{
			subkey = (Key) e.nextElement();
			Signature[] sigs =
				subkey.verifySignatures(
					this,
					new int[] { Signature.SIGNATURE_SUBKEY_BINDING },
					0,
					true);
			if (sigs.length == 0)
				throw new MissingSelfSignatureException(
					"No signature on subkey: "
						+ Conversions.bytesToHexString(subkey.getKeyID())
						+ " by key "
						+ Conversions.bytesToHexString(getKeyID()));
		}

	}

	/**
	 * This function is for use with two keys that have the same key ID.
	 * It merges all the information in the key passed as a parameter 
	 * into the object upon which the method is called.
	 * <p>
	 * It will recursively merge all subkeys.
	 * <p>
	 * All signatures, user ID's, user attributes, and trust info,
	 * on the parameter key will be added
	 * to the object.  This may result in duplicates.
	 * 
	 * @param key the key to merge into this object
	 * @throws IllegalArgumentException if the key ID's don't match
	 */
	public void merge(Key key)
	{
		if (!ArrayTools.equals(getKeyID(), key.getKeyID()))
			throw new IllegalArgumentException("Cannot merge two keys that do not have the same key ID");
		if (key.getSecretKeyMaterial() != null)
			setSecretKeyMaterial(key.getSecretKeyMaterial());
		Signature[] newSigs = key.getSignatures(-1, null);
		for (int x = 0; x < newSigs.length; x++)
			addSignature(newSigs[x]);
		UserID[] newUIDs = key.getUserIDs();
		for (int x = 0; x < newUIDs.length; x++)
			addUserID(newUIDs[x]);
		UserAttribute[] newUAttrs = key.getUserAttributes();
		for (int x = 0; x < newUAttrs.length; x++)
			addUserAttribute(newUAttrs[x]);
		byte[][] trustInfo = key.getTrustInformation();
		for (int x = 0; x < trustInfo.length; x++)
			addTrustInformation(trustInfo[x]);
		Key[] subkeys = key.getSubkeys();
		for (int x = 0; x < subkeys.length; x++)
			addSubkey(subkeys[x]);
	}

	/**
	 * Pair-wise consistency check conforming to
	 * FIPS140-2.
	 */
	public void test(SecureRandom random)
	{
		byte[] input = null;

		try
		{
			if (algorithm == CIPHER_DSA)
			{
				DSASigner dsaSigner = new DSASigner();
				dsaSigner.init(
					true,
					new ParametersWithRandom(getSecretKey(), random));
				input = new byte[20];
				random.nextBytes(input);
				BigInteger[] sig = dsaSigner.generateSignature(input);
				DSASigner dsaVerifier = new DSASigner();
				dsaVerifier.init(false, getPublicKey());
				if (!dsaVerifier.verifySignature(input, sig[0], sig[1]))
					throw new RuntimeException(
						"Signature creation/verification failed for newly created key - Test data: "
							+ Conversions.bytesToHexString(input));
			}
			else
			{
				AsymmetricBlockCipher encrypt = null;
				if (algorithm == CIPHER_ELGAMAL
					|| algorithm == CIPHER_ELGAMAL_ENCRYPT_ONLY)
				{
					encrypt = new PKCS1Encoding(new ElGamalEngine());
				}
				else if (
					algorithm == CIPHER_RSA
						|| algorithm == CIPHER_RSA_ENCRYPT_ONLY
						|| algorithm == CIPHER_RSA_SIGN_ONLY)
				{
					encrypt = new PKCS1Encoding(new RSAEngine());
				}
				encrypt.init(true, getPublicKey());
				input = new byte[16];
				random.nextBytes(input);
				byte[] output = encrypt.processBlock(input, 0, input.length);
				if (ArrayTools.equals(input, output))
					throw new RuntimeException(
						"Input and output to encryption function were equivalent - Test data: "
							+ Conversions.bytesToHexString(input));
				AsymmetricBlockCipher decrypt = null;
				if (algorithm == CIPHER_ELGAMAL
					|| algorithm == CIPHER_ELGAMAL_ENCRYPT_ONLY)
				{
					decrypt = new PKCS1Encoding(new ElGamalEngine());
				}
				else if (
					algorithm == CIPHER_RSA
						|| algorithm == CIPHER_RSA_ENCRYPT_ONLY
						|| algorithm == CIPHER_RSA_SIGN_ONLY)
				{
					decrypt = new PKCS1Encoding(new RSAEngine());
				}
				decrypt.init(false, getSecretKey());
				byte[] decryptedOutput =
					decrypt.processBlock(output, 0, output.length);
				if (!ArrayTools.equals(input, decryptedOutput))
					throw new RuntimeException(
						"Failed to decrypt data encrypted with new key - Test data: "
							+ Conversions.bytesToHexString(input)
							+ " Output: "
							+ Conversions.bytesToHexString(decryptedOutput));
			}
		}
		catch (InvalidCipherTextException e)
		{
			ExceptionWrapper.wrapInRuntimeException("Failed testing new key - Test data: "
					+ Conversions.bytesToHexString(input), e);
		}
	}

	/**
	 * @return the keyType
	 */
	public KeyType getKeyType() 
	{
		if (keyType == null) {
			Signature[] sigs = getSignatures(-1, null);
			for (int i = 0; sigs != null && i < sigs.length; i++) {
				KeyFlags keyFlags = sigs[i].getKeyFlags(false);
				if (keyFlags != null) {
					if ((keyFlags.encryptCommunications || keyFlags.encryptStorage) && keyFlags.signData) 
					{
						keyType = KeyType.BOTH;
					}
					else if (keyFlags.encryptCommunications || keyFlags.encryptStorage) 
					{
						keyType = KeyType.ENCRYPTION;
					} 
					else if (keyFlags.signData) 
					{
						keyType = KeyType.SIGNING;
					}
				}
			}
		}
		return keyType;
	}

	/**
	 * @param keyType the keyType to set
	 */
	public void setKeyType(KeyType keyType) 
	{
		if (keyType == null) {
			throw new IllegalArgumentException("Unsepcified Key Type.");
		}
		// TODO Sean: Should we prevent the key type from been changed?
		this.keyType = keyType;
	}

	/* (non-Javadoc)
	 * @see com.hush.pgp.Signable#sign(com.hush.pgp.Signature, com.hush.pgp.Key, int, long, java.security.SecureRandom)
	 */
	public void sign(Signature signature, Key signer, int signatureType,
			long creationTime, SecureRandom random)
			throws UnrecoverableKeyException 
	{
		updateKeyFlags(signature);
		super.sign(signature, signer, signatureType, creationTime, random);
	}

	/**
	 * Updates the KeyFlags to reflect the key type. 
	 * @param signature
	 */
	private void updateKeyFlags(Signature signature) 
	{
		if (getKeyType() != null) 
		{
			// Make sure that we do not replace the existing flags as this may be a call to re-sign the data
			if (signature.getKeyFlags(true) == null) {
				signature.setKeyFlags(getKeyType().getKeyFlags(), false, false);
			}
		}
	}
}
