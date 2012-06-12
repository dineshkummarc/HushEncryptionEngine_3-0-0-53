/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.hee;

import java.awt.Dimension;
import java.awt.FileDialog;
import java.beans.IntrospectionException;
import java.beans.Introspector;
import java.beans.PropertyDescriptor;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.MalformedURLException;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Properties;
import java.util.Vector;

import org.bouncycastle.crypto.Digest;

import com.hush.applet.security.Badge;
import com.hush.applet.security.Strategy;
import com.hush.awt.GenericIndicator;
import com.hush.hee.keyserver.GeneratedPassword;
import com.hush.hee.keyserver.Keyserver;
import com.hush.hee.keyserver.MailServerInformation;
import com.hush.hee.legacy.LegacyDataFormatException;
import com.hush.hee.legacy.LegacyHushmail;
import com.hush.hee.net.KeyserverClient;
import com.hush.hee.util.FileUtilities;
import com.hush.hee.util.StringReplace;
import com.hush.io.ContentLengthOutputStream;
import com.hush.io.DumpInputStream;
import com.hush.io.ProgressIndicatorInputStream;
import com.hush.net.HttpRequest;
import com.hush.pgp.AlgorithmFactory;
import com.hush.pgp.CanonicalSignedMessage;
import com.hush.pgp.DataFormatException;
import com.hush.pgp.InvalidSignatureException;
import com.hush.pgp.Key;
import com.hush.pgp.Keyring;
import com.hush.pgp.MissingSelfSignatureException;
import com.hush.pgp.PgpConstants;
import com.hush.pgp.S2kAlgorithm;
import com.hush.pgp.Signature;
import com.hush.pgp.UserID;
import com.hush.pgp.io.IntegrityCheckFailureException;
import com.hush.pgp.io.NoSessionKeyException;
import com.hush.pgp.io.PgpMessageInputStream;
import com.hush.pgp.io.PgpMessageOutputStream;
import com.hush.util.ArrayTools;
import com.hush.util.Conversions;
import com.hush.util.Conversions2;
import com.hush.util.ExceptionWrapper;
import com.hush.util.Logger;
import com.hush.util.UnrecoverableKeyException;

/**
 * This provides the core functionality for the HushEncryptionEngine.
 * <br>
 * Do NOT add convenience access methods to this class.  The "easy" interface
 * should be on whatever class wraps this one. -sbs
 * <br>
 * Note on character encodings: aliases, email addresses, and passphrases
 * are always assumed to be UTF-8.  ASCII armored data is assumed to be ASCII.
 * Actual data is always in byte array form, so no need to worry about
 * converting that in this class.
 */
public class HushEncryptionEngineCore implements PgpConstants, Serializable,
	SecureRandomCallback
{
	private static final long serialVersionUID = -8640765311219436775L;

	public final static int BAD_PASSPHRASE = 1;
	public final static String DEFAULT_FORMAT = "PGP";
	public final static int ENCRYPTION_KEY_SIZE = 2048;
	public final static int ERROR = -1;
	public final static int HTTP_GET = 0;
	public final static int HTTP_POST = 1;

	public final static String KEYBLOCKS_PARAMETER = "keyblocks";
	public final static int LOAD = FileDialog.LOAD;
	public final static int NO_CERTIFICATE_FOUND = 2;
	public final static int NO_SIGNATURE_FOUND = 3;
	public final static String PRNG = "SHA1BlumBlumShub";
	public final static int SAVE = FileDialog.SAVE;
	public final static int SIGNATURE_INVALID = 1;
	public final static int SIGNATURE_KEY_SIZE = 1024;
	public final static int SIGNATURE_VALID = 0;
	public final static int SUCCESS = 0;
	
	public final static long[] ENGINE_VERSION = new long[]{3,0,0,53};
	
	public static final String[][] parameterInfo =
	{
			{ "cachePasswords", boolean.class.getName(),
					"Optional. In symmetric decryption, reuse most recently used password." },
			{ "connectTimeout", int.class.getName(),
					"Optional. Java 1.4 and higher. A timeout for connections." },

			{
					"customerID",
					String.class.getName(),
					"Mandatory. The customer ID for the domain on which you wish to"
							+ " create aliases." },
			{ "forgiveBadRandomSeed", boolean.class.getName(),
					"Optional. If true, continue if random seed decryption fails." },
			{
					"keyserver",
					String[].class.getName(),
					"Deprecated. The address of the default server on the Hush Key"
							+ " Server Network to which the applet should connect." },
			{ "logLevel", int.class.getName(),
					"Optional.  Sets log level in com.hush.util.Logger." },
			{
					"lookupKeyservers",
					String[].class.getName(),
					"Mandatory. Comma-separated list of the servers on the Hush Key"
							+ " Server Network to which the applet should connect for lookup"
							+ " (read-only) operations." },

			{
					"newEncryptionKeyAlgorithm",
					String.class.getName(),
					"Optional. Algorithm to use for new encryption keys.  See com.hush.pgp.PgpConstants.PUBLIC_KEY_CIPHER_STRINGS." },
			{ "newEncryptionKeySize", int.class.getName(),
					"The size in bits for new encryption keys." },
			{
					"newKeySignatureHashAlgorithm",
					String.class.getName(),
					"Options. Hash algorithm to use when signing new keys.  See com.hush.pgp.PgpConstants.HASH_STRINGS." },
			{
					"newSigningKeyAlgorithm",
					String.class.getName(),
					"Optional. Algorithm to use for new signing keys.  See com.hush.pgp.PgpConstants.PUBLIC_KEY_CIPHER_STRINGS." },
			{ "newSigningKeySize", int.class.getName(),
					"The size int bits for new signing keys." },
			{ "pgpCertificateAuthorityCertificate", String.class.getName(),
					"Optional. Override the default CA." },
			{ "pgpMessageHeader", String.class.getName(),
					"Optional. The header for PGP messages" },
			{ "pgpSignatureHeader", String.class.getName(),
					"Optional. The header for PGP signatures" },
			{ "newPrivateAliasHashAlgorithm", String.class.getName(),
					"Optional. Sets default hash for new account private aliases." },
			{ "newPrivateAliasIterationCount", int.class.getName(),
					"Optional. Sets default iterations for new account private aliases." },
			{
					"randomSeedUpdateCycle",
					int.class.getName(),
					"Optional. If greater than zero, the random seed will be updated on the keyserver on a cycle measured in seconds." },
			{
					"randomSeedUpdateOnFinalize",
					boolean.class.getName(),
					"Update the random seed when the HushEncryptionEngine is finalized. Defaults to false." },
			{ "readTimeout", int.class.getName(),
					"Optional. Java 1.4 and higher. A timeout for socket reads." },
			{ "testAlgorithms", boolean.class.getName(),
					"Optional. Default false. If true, run algorithm tests at startup." },
			{
					"signatureHashAlgorithm",
					String.class.getName(),
					"Optional. Specified an hash algorithm to be used in signatures other than signatures of new keys. See com.hush.pgp.PgpConstants.HASH_STRINGS." },
			{
					"signPublicKeyLookupRequests",
					boolean.class.getName(),
					"Optional. Default false. When authenticated, sign public key lookup requests sent to the keyserver." },
			{
					"updateKeyservers",
					String[].class.getName(),
					"Mandatory. Comma-separated list of the servers on the Hush Key"
							+ " Server Network to which the applet should connect for update"
							+ " (write) operations." },
			{
					"useProgressIndicators",
					boolean.class.getName(),
					"Optional. Default false. Indicates whether progress indicators"
							+ " should be displayed during streaming operations." }

	};
	
	private static PropertyDescriptor[] propertyDescriptors;
	static
	{
		try
		{
			propertyDescriptors = Introspector.getBeanInfo(HushEncryptionEngineCore.class).getPropertyDescriptors();
		}
		catch(IntrospectionException e)
		{
			// Should never happen
			throw ExceptionWrapper.wrapInRuntimeException("This should never happen", e);
		}
	}
			
	private boolean anonymous = false;
	private String authenticatedAlias = null;

	private KeyManagementServices kms;
	private Keyserver keyserver;
	private Vector loginCredentials = null;

	private Hashtable messageHeaders = new Hashtable();

	/** Length (in bytes) for preactivation code. */
	private int preactivationCodeLength = 16;

	/**
	 * The length of the cycle on which the random seed is updated.
	 */
	private int randomSeedUpdateCycle = -1;
	private boolean randomSeedUpdateOnFinalize = false;
	private transient Thread randomSeedUpdateThread = null;
	private Hashtable signatureHeaders = new Hashtable();
	private boolean useArmor = false;
	private boolean useProgressIndicators = false;

	private boolean cachePasswords = false;
	private int symmetricEncryptionAlgorithm = CIPHER_AES256;
	private int signatureHashAlgorithm = -1;
	
	private SecureRandomCallback secureRandomCallback;
	
	public HushEncryptionEngineCore()
	{
		super();
		messageHeaders.put(ARMOR_HEADER_KEY_VERSION, VERSION);
		signatureHeaders.put(ARMOR_HEADER_KEY_VERSION, VERSION);
		signatureHeaders
				.put("Note",
						"This signature can be verified at https://www.hushtools.com/verify");
		kms = new KeyManagementServices(this);
	}
	
	public Keyserver getKeyserverImplementation()
	{
		assertKeyserverInstalled();
		return this.keyserver;
	}
	
	/**
	 * Retrieves the instance of KeyManagementServices used by this class.
	 *
	 * @return the instance
	 */
	public KeyManagementServices getKms()
	{
		assertKeyserverInstalled();
		return kms;
	}
	
	public void setKeyserverImplementation(Keyserver keyserverImplementation)
	{
		if ( this.keyserver != null )
		{
			throw new IllegalStateException("Too late to set keyserver implementation");
		}
		this.keyserver = keyserverImplementation;
		kms.setKeyserver(keyserverImplementation);
	}
	
	private void assertKeyserverInstalled()
	{
		if ( keyserver != null ) return;
		this.setKeyserverImplementation(new KeyserverClient());
	}
	
	public void setSecureRandomCallback(SecureRandomCallback secureRandomCallback)
	{
		if ( this.secureRandomCallback != null )
		{
			throw new IllegalStateException("secureRandomCallback was already set");
		}
		this.secureRandomCallback = secureRandomCallback;
	}
	
	public void init(Parameterized parameterized, SecureRandom random)
	{
		if ( random != null ) setSecureRandom(random);
		if ( parameterized != null )setParametersFromParameterized(parameterized);
	}
	
	protected void addPasswords(PgpMessageInputStream pgpIn, byte[][] passwords)
	{
		if ( passwords != null )
		{
			for (int x=0;x<passwords.length;x++)
			{
				if ( passwords[x] != null && passwords[x].length > 0 )
				{
					pgpIn.addPassword(passwords[x]);
				}
			}
		}
		if ( ! cachePasswords ) return;
		byte[][] cachedPasswords = getKms().getCachedPasswords();
		for(int x=0; x<cachedPasswords.length;x++)
		{
			if ( cachedPasswords[x] == null ) continue;
			byte[] password = cachedPasswords[x];
			if ( password != null && password.length > 0 )
			{
				pgpIn.addPassword(password);
			}
		}
	}

	/**
	 * Attempt to authenticate to retrieve private keys and random seed data
	 * from the Hush Key Server Network.
	 * 
	 * @param alias The alias to attempt to authenticate.
	 * @param passphrase The passphrase for this alias
	 * @return SUCCESS (BAD_PASSPHRASE is deprecated, catch an
	 *  UnrecoverableKeyException instead)
	 * @throws UnrecoverableKeyException if there was a bad passphrase
	 * @throws IOException if there was an error communicating with the Key Server
	 * @throws DataFormatException if badly formatted data was returned from the Key Server
	 * @throws KeyStoreException if there was any other sort of error retrieving the keys
	 */
	public int authenticate(String alias, byte[] passphrase)
			throws IOException, KeyStoreException, UnrecoverableKeyException
	{
		updateRandom(new Object[] { alias, passphrase });
		alias = alias.toLowerCase().trim();
		
		Key key = kms.getPrivateKey(alias, passphrase);
		if (key == null)
		{
			getKms().clearPrivateKeyRecord(alias);
			Logger
					.log(this, Logger.ERROR,
							"Unexpected failure to retrieve any private key - this should not occur");
			throw new UnrecoverableKeyException(
					"Unexpected failure retrieve any private key");
		}

		byte[] nonce = new byte[64];
		getKms().getRandom().nextBytes(nonce);
		Signature signingSignature = new Signature();
		signingSignature.startSigning(key, SIGNATURE_ON_BINARY_DOCUMENT, System.currentTimeMillis());
		signingSignature.update(nonce);
		signingSignature.finishSigning(getKms().getRandom());
		String signature = signingSignature.toString();
		
		Key publicKey = null;
		try
		{
			publicKey = kms.getPublicKey(alias, null);
			Signature verificationSignature = Signature.load(signature)[0];
			verificationSignature.startVerification();
			verificationSignature.update(nonce);
			verificationSignature.finishVerification(publicKey);
		}
		catch (InvalidSignatureException e)
		{
			getKms().clearPrivateKeyRecord(alias);
			throw UnrecoverableKeyException.wrap(
					"Could not validate signature made by private key", e);
		}
		
		this.authenticatedAlias = alias;
				
		getKeyserverImplementation().setAuthenticatedUser(alias);		
		// Upgrade the keys if required
		if (kms.validateAndUpgradeKeys(alias, passphrase, key, publicKey)) 
		{
			key = kms.getPrivateKey(alias, passphrase);
		}
		if ( getKeyserverImplementation() instanceof KeyserverClient )
		{			
			((KeyserverClient)getKeyserverImplementation()).setPrivateKey(key);
		}
		
		// Clear any login credentials that might be there from a previous alias
		this.loginCredentials = null;
		
		// Clear cached key records, as the might contained generated
		// password information inherited from the domain of a previous
		// alias.
		kms.clearPublicKeyCache();

		// Start the random seed update cycle if needed.
		if (randomSeedUpdateCycle > -1)
		{
			if (randomSeedUpdateThread != null)
			{
				randomSeedUpdateThread.stop();
			}
			randomSeedUpdateThread = new Thread(new Runnable()
			{
				public void run()
				{
					try
					{
						while (true)
						{
							Thread.sleep(randomSeedUpdateCycle * 1000);
							try
							{
								getKms().saveRandomSeed(getAlias(), null);
							}
							catch (Throwable t)
							{
								Logger.logThrowable(this, Logger.WARNING, "Failed to save random seed", t);
							}
						}
					}
					catch (InterruptedException e)
					{
						Logger.logThrowable(this, Logger.INFO, "Random seed thread interrupted", e);
					}
				}
			});
			randomSeedUpdateThread.start();
		}

		return SUCCESS;

	}
	
	/**
	 * Use char arrays to allow maximum flexibility for
	 * clearing the array in situations where that might
	 * be appropriate.
	 * <p>
	 * Warning, this does not support the Unicode
	 * "supplemental characters".  See http://www.unicode.org/glossary/.
	 */
	public char[] canonicalizePassphrase(char[] passphrase)
	{
		char[] newPassphrase = new char[passphrase.length];
		int n = 0;
		for (int x=0; x<passphrase.length; x++)
		{
			if ( passphrase[x] != '-'
				&& passphrase[x] != '.'
				&& passphrase[x] != ','
				&& ! Character.isWhitespace(passphrase[x])
				)
			{
				newPassphrase[n++] = Character.toLowerCase(passphrase[x]);
			}
		}
		char[] newPassphrase2 = new char[n];
		System.arraycopy(newPassphrase, 0, newPassphrase2, 0, n);
		ArrayTools.wipe(newPassphrase);
		return newPassphrase2;
	}
	
	/**
	 * A method to change login credentials on the Hush Key Server Network.
	 * Authentication is accomplished using the current login credentials
	 * password, which can be retrieved through the
	 * <code>getLoginCredentials</code> method.
	 * 
	 * <p>
	 * Note that if any old information is to be kept, it must be re-added here.
	 * </p>
	 * 
	 * @deprecated
	 * 
	 * @param oldPassword the original password
	 * @param newUsername the username to be stored
	 * @param newPassword the password to be stored
	 * @param newHostname the hostname to be stored
	 */
	public void changeLoginCredentials(
		String oldPassword,
		String newUsername,
		String newPassword,
		String newHostname)
		throws KeyStoreException
	{
		updateRandom(
			new Object[] {
				oldPassword,
				newUsername,
				newPassword,
				newHostname });

		checkAuthentication();
		
		getKeyserverImplementation().changeEmailPassword(authenticatedAlias, oldPassword,
				newPassword);

		Vector loginCredentials = new Vector();
		loginCredentials.addElement(newUsername);
		loginCredentials.addElement(newPassword);
		loginCredentials.addElement(newHostname);
		this.loginCredentials = loginCredentials;
	}

	/**
	 * Attempt to change the passphrase of the given alias.
	 * 
     * This method will then authenticate as the changed user,
     * unless some other user is already authenticated.
	 * 
	 * @param alias the alias to change the passphrase for
	 * @param oldPassphrase the current passphrase for this alias
	 * @param newPassphrase the new passphrase for this alias
	 * @return the new passphrase shadows or null if N/A
	 * @throws UnrecoverableKeyException if there was a bad passphrase
	 * @throws IOException if there was an error communicating with the Key Server
	 * @throws DataFormatException if badly formatted data was returned from the Key Server
	 * @throws KeyStoreException if there was any other sort of error retrieving the keys
	 */
	public String[] changePassphrase(
		String alias,
		byte[] oldPassphrase,
		byte[] newPassphrase)
		throws IOException, KeyStoreException, UnrecoverableKeyException
	{
		updateRandom(new Object[]
		{ oldPassphrase, newPassphrase });
		alias = alias.toLowerCase().trim();
		String originalAuthAlias = getAlias();
		boolean alreadyAuthAsOtherUser
			= originalAuthAlias != null && !alias.equals(originalAuthAlias);
		try
		{
			if (!alias.equals(originalAuthAlias))
			{
				// Authenticate here, so that the Keyserver interface
				// will have permissions to store a passphrase component
				// if necessary
				authenticate(alias, oldPassphrase);
			}
			String[] result = getKms().changePassphrase(alias, oldPassphrase,
					newPassphrase);
			if (!alreadyAuthAsOtherUser)
				authenticate(alias, null);
			return result;
		}
		finally
		{
			if (alreadyAuthAsOtherUser)
			{
				getKms().clearPrivateKeyRecord(alias);
				authenticate(originalAuthAlias, null);
			}
		}
	}

	/**
	 * Check to see if an alias is available on the Key Server Network. Should
	 * be called be creating a key record.
	 * 
	 * @param alias the alias to check the availability of
	 * @return true if the alias is available, false if it is not
	 */
	public boolean checkAliasAvailability(String alias)
		throws KeyStoreException
	{
		updateRandom(new Object[] { alias });
		// Return whether or not the alias is available.
		alias = alias.toLowerCase().trim();

		return getKms().isAliasAvailable(alias);
	}

	/**
	 * Confirm that a private key has been retrieved and cached.
	 */
	public void checkAuthentication()
	{
		if (authenticatedAlias == null)
			throw new NeedsAuthenticationException();
	}

	/**
	 * Checks to see if certificates are available for the aliases passed in the
	 * Vector.
	 * 
	 * @param aliases a list of aliases to check
	 * @return a Vector of aliases for which no public keys were found
	 */
	public Vector checkForCertificates(Vector aliases)
	{
		//TODO: Throw an exception if keyserver connection is problem. -sbs
		updateRandom(new Object[] { aliases });
		Vector failures = new Vector();
		Enumeration aliasesE = aliases.elements();

		while (aliasesE.hasMoreElements())
		{
			String thisAlias = (String) aliasesE.nextElement();
			try
			{
				if (retrieveCertificate(thisAlias) == null)
				{
					failures.addElement(thisAlias);
				}
			}
			catch (Exception e)
			{
				Logger.logThrowable(this, Logger.DEBUG,
					"Failure to retrieve certificate", e);
				failures.addElement(thisAlias);
			}
		}

		return failures;
	}

	/**
	 * Connect to a specified URL and copy the contents to a file, decrypting it
	 * if that operation is requested.
	 * <br>
	 * If a ".asc" filename is specified and the data is encrypted, the file
	 * will be renamed without the extension, unless a file with that name already
	 * exists.
	 * 
	 * @param url the URL to retrieve
	 * @param filepath the location to save the URL contents
	 * @param password attempt to symmetrically decrypt the URL data with this password
	 * @param symmetric attempt symmetric decryption
	 * @param mode HTTP_GET or HTTP_POST
	 * @param form a form to send to the URL, as a set of key/value pairs
	 * @param decrypt attempt decryption
	 * @return the full path to the file in which the data is stored
	 */
	public String copyUrlToFile(
		String url,
		final String filepath,
		final byte[] password,
		Hashtable parameters,
		int mode,
		Hashtable form,
		boolean decrypt,
		String signature,
		Vector validSigners,
		Vector invalidSigners)
		throws
			MalformedURLException,
			IOException,
			KeyStoreException,
			DataFormatException,
			NoSessionKeyException,
			IntegrityCheckFailureException
	{
		updateRandom(
			new Object[] {
				url,
				filepath,
				password,
				parameters,
				new Integer(mode),
				form,
				new Boolean(decrypt)});
		if (decrypt && password == null)
			checkAuthentication();
		GenericIndicator myGenericIndicator = null;

		try
		{
			Signature[] signatureArray = new Signature[0];
			if (signature != null
				&& !"".equals(signature)
				&& validSigners != null
				&& invalidSigners != null)
			{
				signatureArray =
					Signature.load(
						new ByteArrayInputStream(Conversions.stringToByteArray(signature, UTF8)));
			}

			for (int x = 0; x < signatureArray.length; x++)
			{
				signatureArray[x].startVerification();
			}

			HttpRequest request;

			if (mode == HTTP_POST)
			{
				request =
					new HttpRequest(url, true, HttpRequest.MULTIPART_FORM_DATA);
			}
			else
			{
				request = new HttpRequest(url);
			}

			if (form != null)
				request.setForm(form);

			if (useProgressIndicators)
			{
				myGenericIndicator = new GenericIndicator();
				myGenericIndicator.setSize(new Dimension(275, 75));
				myGenericIndicator.setFinishedText("Finished.");
				myGenericIndicator.setTitle("Progress");
				myGenericIndicator.setVisible(true);
			}

			request.open();

			request.connect();

			ProgressIndicatorInputStream socketStream =
				new ProgressIndicatorInputStream(
					new BufferedInputStream(request.getInputStream()),
					request.contentLength(),
					myGenericIndicator);

			FileOutputStream fs =
				new FileUtilities().getFileOutputStream(new File(filepath));

			BufferedOutputStream outStream = new BufferedOutputStream(fs);

			InputStream streamToReadFrom;

			boolean isPGPMessage = false;
			PgpMessageInputStream pgpStream = null;

			if (!decrypt)
			{
				streamToReadFrom = socketStream;
			}
			else if (
				parameters != null
					&& parameters.get(KEYBLOCKS_PARAMETER) != null
					&& !"".equals(parameters.get(KEYBLOCKS_PARAMETER)))
			{
				ByteArrayOutputStream storeHere = new ByteArrayOutputStream();

				byte[] buffer = new byte[512];
				int x;
				while ((x = socketStream.read(buffer)) != -1)
					storeHere.write(buffer, 0, x);

				streamToReadFrom =
					new ByteArrayInputStream(
						legacyHushmailDecryption(
							Conversions.byteArrayToString(
								storeHere.toByteArray(),
								UTF8),
							parameters));
			}
			else
			{
				// Create a temporary buffer in case decryption fails
				// and we need to dump the extra bytes to a file.
				ByteArrayOutputStream dumpBufferStream =
					new ByteArrayOutputStream();
				DumpInputStream dumpSocketStream =
					new DumpInputStream(socketStream, dumpBufferStream);

				pgpStream = new PgpMessageInputStream(dumpSocketStream);

				if (password != null && password.length > 0)
				{
					pgpStream.addPassword(password);
				}

				if (authenticatedAlias != null)
					pgpStream.addKeyring(
						getKms().getPrivateKeyring(authenticatedAlias, null));
				streamToReadFrom = pgpStream;

				// read one byte, to see if the stream is really encrypted and in a
				// proper format
				try
				{
					int oneByte = streamToReadFrom.read();
					outStream.write(oneByte);
					for (int x = 0; x < signatureArray.length; x++)
					{
						signatureArray[x].update(new byte[] {(byte) oneByte });
					}
					isPGPMessage = true;
				}
				catch (DataFormatException e)
				{
					Logger.logThrowable(this, Logger.INFO,
						"Not a valid OpenPGP message - treating as unencrypted data", e);
					// Decryption failed, so write the stored bytes
					outStream.write(dumpBufferStream.toByteArray());
					for (int x = 0; x < signatureArray.length; x++)
					{
						signatureArray[x].update(
							dumpBufferStream.toByteArray());
					}
					streamToReadFrom = socketStream;
				}
				catch (NoSessionKeyException e)
				{
					Logger.logThrowable(this, Logger.INFO,
						"Could not decrypt a session key for the message - saving without decrypting", e);
					// Decryption failed, so write the stored bytes
					outStream.write(dumpBufferStream.toByteArray());
					streamToReadFrom = socketStream;
					signatureArray = new Signature[0];
				}
				catch (Exception e)
				{
					Logger.logThrowable(this, Logger.INFO,
						"Caught an unexpected exception while attempting decryption - will attempt to save without decrypting", e);
					// Decryption failed, so write the stored bytes
					outStream.write(dumpBufferStream.toByteArray());
					for (int x = 0; x < signatureArray.length; x++)
					{
						signatureArray[x].update(
							dumpBufferStream.toByteArray());
					}
					streamToReadFrom = socketStream;
				}

				dumpSocketStream.setDumping(false);
			}

			byte[] buffer = new byte[512];
			int x;
			while ((x = streamToReadFrom.read(buffer)) != -1)
			{
				outStream.write(buffer, 0, x);
				for (int xx = 0; xx < signatureArray.length; xx++)
				{
					signatureArray[xx].update(buffer, 0, x);
				}
			}

			outStream.flush();
			outStream.close();
			
			try
			{
				// In some cases, closing the wrapping
				// BufferedOutputStream closes the file,
				// in some cases not.  Try to close it anyway.
				fs.close();
			}
			catch(Throwable t)
			{
			}
			
			streamToReadFrom.close();
			if (streamToReadFrom != socketStream)
				socketStream.close();

			if (signatureArray.length == 0
				&& isPGPMessage
				&& validSigners != null
				&& invalidSigners != null)
				signatureArray = pgpStream.getSignatures();

			finishSignatureVerification(null, signatureArray, validSigners, invalidSigners);
			
			if (myGenericIndicator != null)
			{
				myGenericIndicator.setVisible(false);
			}

			if (isPGPMessage
				&& filepath.length() > 4
				&& filepath.substring(
					filepath.length() - 4,
					filepath.length()).equalsIgnoreCase(
					".asc"))
			{
				String newFilepath =
					filepath.substring(0, filepath.length() - 4);
				if (new File(newFilepath).exists())
				{
					int n = 1;
					int dotIndex = newFilepath.lastIndexOf(".");
					String baseName = newFilepath;
					do
					{
						if (dotIndex != -1)
						{
							newFilepath =
								baseName.substring(0, dotIndex)
									+ "("
									+ n
									+ ")"
									+ baseName.substring(dotIndex);
						}
						else
						{
							newFilepath = baseName + "(" + n + ")";
						}
						n++;
					}
					while (new File(newFilepath).exists());
				}
				new FileUtilities().rename(
					new File(filepath),
					new File(newFilepath));

				return newFilepath;
			}

			return filepath;
		}
		finally
		{
			if (myGenericIndicator != null)
			{
				myGenericIndicator.setVisible(false);
			}
		}
	}
	
	/**
	 * This method should be called after collectEntropy to create keys for an
	 * alias and passphrase.
	 * 
	 * @param alias the alias to create keys for.
	 * @param passphrase the passphrase for this alias.
	 * @param useSharedSecret whether the passphrase should be split between
	 *        three parties.
	 * @param preActivationCode the one-time use code required to create the
	 *        account (for identity-binding purposes)
	 * @return passphrase shadows, or null
	 */
	public String[] createKeyRecord(
		String alias,
		byte[] passphrase,
		boolean useSharedSecret,
		String preActivationCode)
		throws KeyStoreException, UnrecoverableKeyException
	{
        return createKeyRecord(
                alias, passphrase, useSharedSecret, preActivationCode, null
        );
	}

    /**
     * This method should be called after collectEntropy to create keys for an
     * alias and passphrase.
     * 
     * This method will not authenticate as the newly created user.
     * If some other user is already authenticated, that user will
     * remain authenticated.
     * 
     * @param alias the alias to create keys for.
     * @param passphrase the passphrase for this alias.
     * @param useSharedSecret whether the passphrase should be split between
     *        three parties.
     * @param preActivationCode the one-time use code required to create the
     *        account (for identity-binding purposes)
     * @param encryptionMethod the method of encryption to use with this
     *        public key - can be one of "Normal" (recommended), "Web" (for
     *        Hushmail Express-style encryption), or "None" (do not encrypt).
     * @return passphrase shadows, or null
     */
    public String[] createKeyRecord(
        String alias,
        byte[] passphrase,
        boolean useSharedSecret,
        String preActivationCode,
        String encryptionMethod)
        throws KeyStoreException, UnrecoverableKeyException
    {
        updateRandom(
            new Object[] {
                alias,
                passphrase,
                new Boolean(useSharedSecret),
                preActivationCode });
        alias = alias.toLowerCase().trim();
		String originalAuthAlias = getAlias();
		try
		{
			String[] shadows = getKms().createKeyRecord(alias, passphrase,
					preActivationCode, useSharedSecret, encryptionMethod);
			return shadows;
		}
		finally
		{
			if ( originalAuthAlias != null )
			{
				getKms().clearPrivateKeyRecord(alias);
			}
		}
    }
    
	/**
	 * Perform the decryption operation
	 * 
	 * @param toDecrypt the bytes to decrypt
	 * @param parameters optional parameters
	 * @return the decrypted bytes
	 */
	public byte[] decrypt(byte[] toDecrypt, Hashtable parameters)
		throws
			IOException,
			DataFormatException,
			NoSessionKeyException,
			IntegrityCheckFailureException
	{
		return decrypt(toDecrypt, parameters, null);
	}

	/**
	 * Perform the decryption operation
	 * 
	 * @param toDecrypt the bytes to decrypt
	 * @param parameters optional parameters
	 * @param passwords a list of passwords to try when decrypting
	 * @return the decrypted bytes
	 */
	public byte[] decrypt(byte[] toDecrypt, Hashtable parameters,
			byte[][] passwords) throws IOException, DataFormatException,
			NoSessionKeyException, IntegrityCheckFailureException
	{
		return decrypt(toDecrypt, parameters, passwords, null);
	}
	
	private byte[] decrypt(
			byte[] toDecrypt,
			Hashtable parameters,
			byte[][] passwords, String[] characterEncoding)
			throws
				IOException,
				DataFormatException,
				NoSessionKeyException,
				IntegrityCheckFailureException
	{	
		try
		{
			updateRandom(new Object[] { toDecrypt, parameters });
			if ( ( ! cachePasswords || getKms().getCachedPasswordCount() == 0 ) && ( passwords == null || passwords.length == 0 ) ) checkAuthentication();

			if (parameters != null
				&& parameters.get(KEYBLOCKS_PARAMETER) != null)
			{
				return legacyHushmailDecryption(
					Conversions.byteArrayToString(toDecrypt, UTF8),
					parameters);
			}

			PgpMessageInputStream decryptionStream =
				new PgpMessageInputStream(new ByteArrayInputStream(toDecrypt));
			decryptionStream.addKeyring(
					getKms().getPrivateKeyring(authenticatedAlias, null));
			addPasswords(decryptionStream, passwords);
			ByteArrayOutputStream result = new ByteArrayOutputStream();
			byte[] buffer = new byte[2048];
			int x;
			while ((x = decryptionStream.read(buffer)) != -1)
			{
				result.write(buffer, 0, x);
			}
			decryptionStream.close();
			if (characterEncoding != null && characterEncoding.length > 0)
				characterEncoding[0] = decryptionStream.getCharacterEncoding();
			// At this point, assume the decryption was successful, so
			// cache the passwords
			getKms().cachePasswords(passwords);
			return result.toByteArray();
		}
		catch (KeyStoreException e)
		{
			throw ExceptionWrapper.wrapInRuntimeException("Keystore exception (account may be deactivated)", e);
		}
	}

	/**
	 * Decrypts a file directly on disk.  The encrypted file is replaced with
	 * the decrypted content.  Authentication must be performed first.
	 * 
	 * @param filename the full path to the file to decrypt
	 * @param parameters information required for decryption in special cases
	 * @param password optional, for password decrypting the file
	 */
	public void decryptFile(
		String filename,
		Hashtable parameters,
		byte[] password)
		throws
			IOException,
			DataFormatException,
			FileNotFoundException,
			NoSessionKeyException,
			IntegrityCheckFailureException
	{
		File tempFile = null;
		FileUtilities util = new FileUtilities();
		try
		{
			tempFile = new FileUtilities().getTempFile(new File(filename));
			decryptFile(
				filename,
				parameters,
				password,
				tempFile.getAbsolutePath());
			File originalFile = new File(filename);
			if (!util.delete(originalFile))
				throw new IOException(
					"Couldn't overwrite " + originalFile.getAbsolutePath());

			if (!util.rename(tempFile, originalFile))
				throw new IOException(
					"Couldn't rename "
						+ tempFile.getAbsolutePath()
						+ " to "
						+ originalFile.getAbsolutePath());
		}
		finally
		{
			try
			{
				util.delete(tempFile);
			}
			catch (Exception e)
			{
			}
		}
	}

	public void decryptFile(
		String inputFilename,
		Hashtable parameters,
		byte[] password,
		String outputFilename)
		throws
			IOException,
			DataFormatException,
			FileNotFoundException,
			NoSessionKeyException,
			IntegrityCheckFailureException
	{
		updateRandom(
			new Object[] {
				inputFilename,
				parameters,
				password,
				outputFilename });

		FileOutputStream outputStream = null;
		FileInputStream originalStream = null;
		File outputFile = null;
		FileUtilities util = new FileUtilities();
		try
		{
			if ( ( ! cachePasswords || getKms().getCachedPasswordCount() == 0 ) && ( password == null || password.length == 0 ) ) checkAuthentication();
			File originalFile = new File(inputFilename);
			outputFile = new File(outputFilename);
			outputStream = util.getFileOutputStream(outputFile);
			originalStream = util.getFileInputStream(originalFile);
			PgpMessageInputStream pgpIn =
				new PgpMessageInputStream(originalStream);
			Keyring decryptionKeys =
				getKms().getPrivateKeyring(authenticatedAlias, null);
			if (decryptionKeys != null)
				pgpIn.addKeyring(decryptionKeys);
			addPasswords(pgpIn, new byte[][]{password});
			byte[] b = new byte[2048];
			int x;
			while ((x = pgpIn.read(b)) != -1)
				outputStream.write(b, 0, x);
			outputStream.close();
			originalStream.close();
			getKms().cachePasswords(new byte[][]{password});
		}
		catch (KeyStoreException e)
		{
			throw ExceptionWrapper
					.wrapInRuntimeException("Keystore exception (account may be deactivated)", e);
		}
		catch (UnrecoverableKeyException e)
		{
			throw ExceptionWrapper
					.wrapInRuntimeException("Exception that should never happen", e);
		}
		finally
		{
			try
			{
				outputStream.close();
			}
			catch (Exception e2)
			{
			}
			try
			{
				originalStream.close();
			}
			catch (Exception e2)
			{
			}
		}
	}

	/**
	 * Decrypts a message and converts it to a String based
	 * on the character encoding specified in the message, or
	 * UTF8 by default.
	 * 
	 * @param toDecrypt the bytes to decrypt
	 * @param parameters optional parameters
	 * @return the decrypted bytes
	 */
	public String decryptText(byte[] toDecrypt, Hashtable parameters)
		throws
			DataFormatException,
			NoSessionKeyException,
			IntegrityCheckFailureException,
			UnsupportedEncodingException,
			IOException
	{
		try
		{
			updateRandom(new Object[] { toDecrypt, parameters });
			checkAuthentication();

			if (parameters != null
				&& parameters.get(KEYBLOCKS_PARAMETER) != null)
			{
				return Conversions.byteArrayToString(
					legacyHushmailDecryption(
						Conversions.byteArrayToString(toDecrypt, UTF8),
						parameters),
					UTF8);
			}

			String[] holder = new String[1];
			byte[] decrypted = decrypt(toDecrypt, parameters, null, holder);
			if (holder[0] == null)
				Conversions.checkCharacterEncoding(holder[0]);
			return Conversions.byteArrayToString(decrypted, holder[0]);
		}
		catch (KeyStoreException e)
		{
			throw ExceptionWrapper
				.wrapInRuntimeException("Keystore exception (account may be deactivated)", e);
		}
	}

	/**
	 * Deletes a file from disk. Primarily for use in conjunction with the
	 * encryptFile() method to delete a plaintext backup.
	 * 
	 * @param src the full path to the file to delete
	 * @return true if successful, false if unsuccessful
	 */
	public boolean deleteFile(String src)
	{
		updateRandom(new Object[] { src });
		return new FileUtilities().delete(new File(src));
	}

	/**
	 * Deletes all public data associated with the given alias.  (Private
	 * data will be uneffected, but that can be overwritten at any time.)
	 */
	public void deleteKeyRecord(String alias)
		throws KeyStoreException
	{
		updateRandom(new Object[] { alias });
		checkAuthentication();
		getKeyserverImplementation().deleteUser(alias);
	}

	/**
	 * This method determines is a wrapper on canEncrypt(SecureMessage) which
	 * assumes that the only information passed in the SecureMessage will be
	 * recipient aliases.
	 * 
	 * @param recipientAliases An array of aliases to wchih a message should be encrypted
	 * @return An array of recipients who do not have keys or the ability to use generated passwords
	 * @throws KeyStoreException
	 * @throws IOException
	 * @throws InvalidSignatureException
	 */
	public String[] canEncrypt(String[] recipientAliases)
			throws KeyStoreException, IOException, InvalidSignatureException,
			MissingSelfSignatureException
	{
		SecureMessage message = createSecureMessage();
		message.setRecipientAliases(recipientAliases);
		return canEncrypt(message);
	}
	
	/**
	 * This method determines which recipients of a SecureMessage do not have
	 * encryption keys or the ability to use generated passwords.  These recipients
	 * will require passwords or questions and answers to be supplied.
	 * 
	 * This *will* modify the recipients list of the SecureMessage, removing
	 * any recipients to whom the message cannot be encrypted.
	 * 
	 * @param message The SecureMessage to encrypt
	 * @return An array of recipients who do not have keys or the ability to use generated passwords
	 * @throws KeyStoreException
	 * @throws IOException
	 * @throws InvalidSignatureException
	 * @throws DeniedException a user is not enabled for encryption
	 */
	public String[] canEncrypt(SecureMessage message) throws KeyStoreException,
			IOException, InvalidSignatureException,
			MissingSelfSignatureException
	{
		CanEncryptResult result = checkCanEncrypt(message);
		if ( result.getDeniedAliases().length > 0 )
		{
			throw new DeniedException(
			"The following recipients cannot receive secure email, probably because they are deactivated: "
					+ Conversions2.stringArrayToString(result.getDeniedAliases(), ","));
		}
		return result.getAliasesWithNoEncryptionMethod();
	}
	
	
	/**
	 * This method determines is a wrapper on canEncrypt(SecureMessage) which
	 * assumes that the only information passed in the SecureMessage will be
	 * recipient aliases.
	 * 
	 * @param recipientAliases An array of aliases to wchih a message should be encrypted
	 * @return An object indicating which recipients have encryption methods,
	 * 	which do not, and which are denied encryption
	 * @throws KeyStoreException
	 * @throws IOException
	 * @throws InvalidSignatureException
	 */
	public CanEncryptResult checkCanEncrypt(String[] recipientAliases)
			throws KeyStoreException, IOException, InvalidSignatureException,
			MissingSelfSignatureException
	{
		SecureMessage message = createSecureMessage();
		message.setRecipientAliases(recipientAliases);
		return checkCanEncrypt(message);
	}
	
	/**
	 * This method determines which recipients of a SecureMessage do not have
	 * encryption keys or the ability to use generated passwords.  These recipients
	 * will require passwords or questions and answers to be supplied.
	 * 
	 * This *will* modify the recipients list of the SecureMessage, removing
	 * any recipients to whom the message cannot be encrypted.
	 * 
	 * @param message The SecureMessage to encrypt
	 * @return An object indicating which recipients have encryption methods,
	 * 	which do not, and which are denied encryption
	 * @throws KeyStoreException
	 * @throws IOException
	 * @throws InvalidSignatureException
	 * @throws DeniedException a user is not enabled for encryption
	 */
	public CanEncryptResult checkCanEncrypt(SecureMessage message) throws KeyStoreException,
		IOException, InvalidSignatureException, MissingSelfSignatureException
	{
		Vector hasEncryptionMethod = new Vector();
		Vector noEncryptionMethod = new Vector();
		Vector denied = new Vector();
        
		String[] recipientAliasesArray = message.getRecipientAliases();
		
		if ( recipientAliasesArray.length == 0 )
			return new CanEncryptResult(new String[0], new String[0], new String[0]);
		
		// See who has encryption methods available on the server.
        Vector recipientAliases = Conversions2.arrayToVector(recipientAliasesArray);
        
		for (int i = 0; i < recipientAliases.size(); i++)
		{
			try
			{
				getKms().getEncryptionObjects(new String[]{(String)recipientAliases.elementAt(i)});
				hasEncryptionMethod.addElement((String)recipientAliases.elementAt(i));
			}
			catch (NoEncryptionMethodException e)
			{
				noEncryptionMethod.addElement((String)recipientAliases.elementAt(i));
			}
			catch(DeniedException e)
			{
				denied.addElement((String)recipientAliases.elementAt(i));
			}
		}
		
		// If this person has a question & answer specified, we don't need to include them
		QuestionAndAnswer[] qa = message.getQuestionsAndAnswers();
		if (qa != null)
		{
			for (int i = 0; i < qa.length; i++)
			{
				String[] recipients = qa[i].getRecipientAliases();
				if ( recipients != null )
				{
					for (int x = 0; x < recipients.length; x++)
					{
						for (int y = 0; y < noEncryptionMethod.size(); y++)
						{
							String alias = (String)(noEncryptionMethod.elementAt(y));
							if (recipients[x].equals(alias))
							{
								noEncryptionMethod.removeElement(alias);
								recipientAliases.removeElement(alias);
							}
						}
					}
				}
			}
		}
		
		Vector hasACert = whoHasAKeyInTheseCerts(message.getRecipientAliases(), message.getCertificates());
		
		if ( hasACert != null )
		{
			for(int x=0; x<hasACert.size(); x++)
			{
				noEncryptionMethod.removeElement((String)hasACert.elementAt(x));
                recipientAliases.removeElement((String)hasACert.elementAt(x));
			}
		}
       
        message.setRecipientAliases(Conversions2.vectorToStringArray(recipientAliases));
        
		return new CanEncryptResult(
				Conversions2.vectorToStringArray(hasEncryptionMethod),
				Conversions2.vectorToStringArray(noEncryptionMethod),
				Conversions2.vectorToStringArray(denied)
		);
	}
	
	/**
	 * Internal method for creating a SecureMessage initialized based
	 * on HEE settings.
	 */
	private SecureMessage createSecureMessage()
	{
		SecureMessage secureMessage = new SecureMessage();
		secureMessage.setAnonymous(getAnonymous());
		secureMessage.setUseArmor(usesArmor());
		return secureMessage;
	}
	
	private Vector whoHasAKeyInTheseCerts(String aliases[], String[] certificates)
		throws IOException, InvalidSignatureException, MissingSelfSignatureException
	{
		if ( certificates == null || certificates.length == 0 || aliases == null
				|| aliases.length == 0 ) return null;
		Vector hasKeys = new Vector();
		for(int x=0; x<certificates.length; x++)
		{
			Keyring kr = new Keyring();
			kr.load(new ByteArrayInputStream(Conversions.stringToByteArray(certificates[x], UTF8)));
			for(int y=0; y<aliases.length; y++)
			{
				Key[] myKeys = kr.getKeys(aliases[y]);
				if ( myKeys.length > 0 ) hasKeys.addElement(aliases[y]);
			}
		}
		return hasKeys;
	}
	
	/**
	 * Perform the encryption operation.
	 * 
	 * @param message
	 *            the message to encrypt
	 * @param sign
	 *            whether or not to sign the message
	 */
	private void processSecureMessage(SecureMessage message, boolean encrypt, boolean sign)
			throws KeyStoreException, NoEncryptionMethodException,
			IOException
	{
		try
		{
			_processSecureMessage(message, encrypt, sign);
		}
		catch (MissingSelfSignatureException exception)
		{
			throw KeyStoreException.wrapInKeyStoreException(
					"Error processing message", exception);
		}
		catch (InvalidSignatureException exception)
		{
			throw KeyStoreException.wrapInKeyStoreException(
					"Error processing message", exception);
		}
		finally
		{
			message.setOutputStream(null);
		}
	}
	
	public PgpMessageOutputStream wrapOutputStreamForEncryption(
			OutputStream outputStream,
			SecureMessage message,
			boolean encrypt, boolean sign) throws UnrecoverableKeyException,
			KeyStoreException, IOException, InvalidSignatureException,
			MissingSelfSignatureException
	{
		// Only make a new AuthInfo if one does not already
		// exist on the object
		AuthInfo authInfo = null;
		if (message.getAuthInfo() == null || message.getAuthInfo().equals(""))
		{
			authInfo = new AuthInfo();
			authInfo.setSender(authenticatedAlias);
		}
		
		// Initialize the PGP output stream
		PgpMessageOutputStream pgpOut = 
			new PgpMessageOutputStream(outputStream, kms.getRandom());
		pgpOut.setPlaintext(! encrypt);
		pgpOut.setSymmetricCipher(
				symmetricEncryptionAlgorithm);		
		pgpOut.setUseArmor(message.getUseArmor());
		if (message.getUseArmor())
		{
			pgpOut.setHeaders(messageHeaders);
		}

		// Add any public keys or random passwords to the PGP output stream.  This
		// list is compiled based on the list of aliases in the SecureMessage object.
		String[] aliases = message.getRecipientAliases();
		if (aliases != null && encrypt)
		{
			Hashtable encryptionObjects = getKms().getEncryptionObjects(aliases);
			Enumeration e = encryptionObjects.keys();
			while (e.hasMoreElements())
			{
				String alias = (String) e.nextElement();
				processEncryptionObject(pgpOut, message, encryptionObjects
						.get(alias), authInfo, alias);
			}
		}
		
		String[] certificates = message.getCertificates();
		if ( certificates != null && encrypt )
		{
			for ( int i=0; i<certificates.length; i++ )
			{
				try
				{
					pgpOut.addRecipient(Keyring.loadKeyring(certificates[i]));
				}
				catch (MissingSelfSignatureException e)
				{
					throw NoEncryptionMethodException.wrapInKeyStoreException(
							"Invalid certificate", e);
				}
				catch (InvalidSignatureException e)
				{
					throw NoEncryptionMethodException.wrapInKeyStoreException(
							"Invalid certificate", e);
				}
			}
		}
		
		// Add any questions and answers to the PGP output stream
		QuestionAndAnswer[] qa = message.getQuestionsAndAnswers();
		if (qa != null && encrypt )
		{
			for (int i = 0; i < qa.length; i++)
			{
				pgpOut.addPassword(Conversions.stringToByteArray(qa[i].getEncryptionKey(), UTF8));
				if (authInfo != null)
						authInfo.addQuestionAndAnswerRecipient(qa[i]);
			}
		}
		
		// Add any passwords to the PGP output stream
		byte[][] passwords = message.getPasswords();
		if (passwords != null && encrypt )
		{
			for (int x = 0; x < passwords.length; x++)
			{
				if (passwords[x] != null)
					pgpOut.addPassword(passwords[x]);
			}
		}
		
		// Are we signing?
		if (sign)
		{
			if (authenticatedAlias == null)
				throw new NeedsAuthenticationException();
			if ( signatureHashAlgorithm != -1 )
				pgpOut.setSignatureHashAlgorithm(signatureHashAlgorithm);
			pgpOut.addOnePassSigner(getKms().getPrivateKey(authenticatedAlias, null));
		}
		
		if (authInfo != null)
			message.setAuthInfo(authInfo.toString());
		
		return pgpOut;
	}
	
	private void _processSecureMessage(SecureMessage message, boolean encrypt,
			boolean sign) throws KeyStoreException, MissingSelfSignatureException,
		InvalidSignatureException, NoEncryptionMethodException, IOException
	{
        message.setOutputBytes(null);
        
		// Initialization
		updateRandom(new Object[] { message });
		
		// Retrieve or create an output stream
		OutputStream outStream = message.getOutputStream();
		if (outStream == null)
		{
			outStream = new ByteArrayOutputStream();
		}
		
		PgpMessageOutputStream pgpOut = wrapOutputStreamForEncryption(outStream, message, encrypt,
				sign);

		// Retrieve or create an input stream
		InputStream inStream = message.getInputStream();
		if (inStream == null)
		{
			inStream = new ByteArrayInputStream(message.getInputBytes());
		}

		// Perform the encryption operation
		byte[] b = new byte[2048];
		int x;
		while ((x = inStream.read(b)) != -1)
			pgpOut.write(b, 0, x);
		inStream.close();			
		pgpOut.close();

		if (message.getOutputStream() == null)
		{
			message.setOutputBytes(((ByteArrayOutputStream)outStream).toByteArray());
		}

		setSignaturesOnMessage(message, ((PgpMessageOutputStream)pgpOut).getOnePassSignatures());

		// Clean up?
		
		/*if (passwordBytes != null)
			ArrayTools.wipe(passwordBytes);*/	
	}
	
	private void processEncryptionObject(PgpMessageOutputStream pgpOut,
			SecureMessage message, Object object, AuthInfo authInfo,
			String alias) throws KeyStoreException, InvalidSignatureException,
				MissingSelfSignatureException
	{
		if (object instanceof KeyRecord)
		{
			KeyRecord record = (KeyRecord)object;
			pgpOut.addRecipient(getKms().getPublicKeyFromRecord(record, null), null, message.getAnonymous());
			Key[] adks = record.adkKeyring.getAllEncryptionKeys();
			for(int i=0; i<adks.length; i++)
			{
				pgpOut.addRecipient(adks[i]);
			}
			if (authInfo != null && record.encryptionMethod != null &&
					record.encryptionMethod.equals(KeyRecord.WEB))
			{
				authInfo.addPublicKeyRecipient(new String[]{record.alias});
			}
		}
		else if (!message.getPublicKeyEncryptionOnly()
				&& object instanceof GeneratedPassword)
		{
			populateGeneratedPassword(pgpOut, message, (GeneratedPassword)object, authInfo, alias);
		}
	}
	
	private void populateGeneratedPassword(PgpMessageOutputStream pgpOut,
			SecureMessage message, GeneratedPassword generatedPassword,
			AuthInfo authInfo, String alias)
			throws NoEncryptionMethodException, KeyStoreException
	{
		String encryptedPassword = null;
		String subject = null;
		String messageID = null;
		
		if (message.getGeneratedPassword() == null)
		{
			message.setGeneratedPassword(
				generatePassword(
					"AAAAA-#####", new char[]{'l','1','L','o','O','0','i','I'}));
		}

		pgpOut.addPassword(Conversions.stringToByteArray(message.getGeneratedPasswordEncryptionKey(), UTF8));
		
		if ( authInfo == null ) return;
		
		// This generated password needs to be emailed
		if (generatedPassword.getMethod().equals(GeneratedPassword.EMAIL));
		{
			SecureMessage encryptedPasswordMessage =
				new SecureMessage();
			encryptedPasswordMessage.setUseArmor(true);
			
			encryptedPasswordMessage.setPublicKeyEncryptionOnly(true);
			
			if (generatedPassword.getPasswordRecipient() == null)
			{
				if (getAlias() == null || getAlias() == "")
				{
					// Should never happen since they must be authenticated
					// prior to signing a request.
					throw new NeedsAuthenticationException();
				}
				encryptedPasswordMessage.setRecipientAliases(
					new String[]{getAlias()});
			}
			else
			{
				encryptedPasswordMessage.setRecipientAliases(
					new String[]{generatedPassword.getPasswordRecipient()});
			}
			
			encryptedPasswordMessage.setUseArmor(true);
			
			messageID = generatePassword("AA-##", new char[]{'l','1','L','o','O','0','i','I'});
			message.setGeneratedPasswordMessageID(messageID);
			
			String text = generatedPassword.getEmailBodyTemplate();
			text = StringReplace.replace(text, "%MESSAGEID%", messageID);
			text = StringReplace.replace(text, "%EMAILRECIPIENT%", alias);
			text = StringReplace.replace(text, "%PASSWORD%", message.getGeneratedPassword());
			text = StringReplace.replace(text, "%NOTES%", encryptedPasswordMessage.getNotes());
			text = StringReplace.replace(text, "\\r", "\r");
			text = StringReplace.replace(text, "\\n", "\n");
			text = StringReplace.replace(text, "\\t", "\t");
			
			subject = generatedPassword.getEmailSubjectTemplate();
			subject = StringReplace.replace(subject, "%MESSAGEID%", messageID);
			subject = StringReplace.replace(subject, "%EMAILRECIPIENT%", alias);
			subject = StringReplace.replace(subject, "%PASSWORD%", message.getGeneratedPassword());
			subject = StringReplace.replace(subject, "%NOTES%", encryptedPasswordMessage.getNotes());
			subject = StringReplace.replace(subject, "\\r", "\r");
			subject = StringReplace.replace(subject, "\\n", "\n");
			subject = StringReplace.replace(subject, "\\t", "\t");
			
			encryptedPasswordMessage.setInputBytes(Conversions.stringToByteArray(text, UTF8));
			try
			{
				processSecureMessage(encryptedPasswordMessage, true, false);
			}
			catch (IOException e)
			{
				throw ExceptionWrapper.wrapInRuntimeException(
						"IOException should never occur here", e);
			}
			encryptedPassword = new String(encryptedPasswordMessage.getOutputBytes());
		}
		authInfo.addGeneratedPasswordRecipient(new String[]{alias},
			messageID,
			encryptedPassword,
			subject,
			message.getGeneratedPassword(),
			message.getGeneratedPasswordSalt(),
			message.getGeneratedPasswordHash(),
			generatedPassword.getMethod().equals(GeneratedPassword.STORE),
			generatedPassword.getPasswordRecipient());
	}
	
	/**
	 * Perform the encryption operation.
	 * @param message the message to encrypt
	 */
	public void encrypt(SecureMessage message) throws KeyStoreException,
			NoEncryptionMethodException, IOException
	{
		processSecureMessage(message, true, false);
	}
	
	/**
	 * Perform the encryption and signing operations.
	 * @param message the message to sign and encrypt
	 */
	public void encryptAndSign(SecureMessage message) throws KeyStoreException,
			NoEncryptionMethodException, IOException
	{
		processSecureMessage(message, true, true);
	}
	
	
	
	/**
	 * Perform the encryption operation.
	 * 
	 * @param toEncrypt the bytes to encrypt.
	 * @param certificates to encrypt to.
	 * @param passwords an array of passwords to encrypt to
	 * @return the encrypted bytes
	 */
	private byte[] encryptPrivate(
		byte[] toEncrypt,
		Vector aliases,
		Vector certificates,
		byte[][] passphrases)
		throws KeyStoreException, IOException,
		NoEncryptionMethodException
	{
		SecureMessage message = createSecureMessage();
		// for legacy reasons, always armor here.
		message.setUseArmor(true);
		if ( aliases != null )
		{
			String[] aliasStrings = new String[aliases.size()];
			aliases.copyInto(aliasStrings);
			message.setRecipientAliases(aliasStrings);
		}
		if ( certificates != null )
		{
			String[] certStrings = new String[certificates.size()];
			certificates.copyInto(certStrings);
			message.setCertificates(certStrings);
		}
		message.setPasswords(passphrases);
		message.setInputBytes(toEncrypt);
		processSecureMessage(message, true, false);
		return message.getOutputBytes();
	}

	/**
	 * Perform the encryption operation.
	 * 
	 * @param toEncrypt the bytes to encrypt.
	 * @param aliases the aliases to encrypt to.
	 * @param certificates to encrypt to
	 * @return the encrypted bytes
	 */
	public byte[] encrypt(
		byte[] toEncrypt,
		Vector aliases,
		Vector certificates)
		throws
			IOException,
			KeyStoreException
	{
		updateRandom(new Object[] { toEncrypt, aliases, certificates });
        return encryptPrivate(toEncrypt, aliases, certificates, null);
	}

	/**
	 * Perform the encryption operation.
	 * 
	 * @param toEncrypt the bytes to encrypt.
	 * @param aliases the aliases to encrypt to.
	 * @param certificates to encrypt to
	 * @return the encrypted bytes
	 */
	public byte[] encrypt(
		byte[] toEncrypt,
		Vector aliases,
		Vector certificates,
		byte[][] passphrases)
		throws
			IOException,
			KeyStoreException,
			NoEncryptionMethodException
	{
		updateRandom(new Object[] { toEncrypt, aliases, certificates });
        return encryptPrivate(toEncrypt, aliases, certificates, passphrases);
	}
	
	/**
	 * Encrypts the data contained in an input file, placing the result in an 
	 * output file.
	 * 
	 * @param inFile the full path to the file for input
	 * @param outFile the full path to the file for output
	 * @param aliases the aliases to encrypt the file to
	 * @param password encrypt the file using this password in addition to
	 *  any public keys specified
	 */
	public void encryptFile(
		String inFile,
		String outFile,
		Vector aliases,
		byte[] password)
		throws IOException, KeyStoreException,
		NoEncryptionMethodException
	{
		SecureMessage message = createSecureMessage();
	
		if ( aliases != null )
		{
			String[] aliasArray = new String[aliases.size()];
			aliases.copyInto(aliasArray);
			message.setRecipientAliases(aliasArray);
		}
			
		FileUtilities util = new FileUtilities();
		FileOutputStream outStream =
			util.getFileOutputStream(new File(outFile));
		FileInputStream inStream = util.getFileInputStream(new File(inFile));

		message.setInputStream(inStream);
		message.setOutputStream(outStream);
		message.setUseArmor(usesArmor());
		message.setPasswords(new byte[][] { password });

		processSecureMessage(message, true, false);
		
		outStream.close();
		inStream.close();
	}

	/**
	 * Encrypts a file directly on disk.
	 * 
	 * @param filename the full path to the file to encrypt
	 * @param aliases the aliases to encrypt the file to
	 * @param password encrypt the file using this password in addition to
	 *  any public keys specified
	 */
	public void encryptFile(String filename, Vector aliases, byte[] password)
			throws IOException, KeyStoreException, NoEncryptionMethodException
	{
		FileUtilities util = new FileUtilities();
		File originalFile = new File(filename);
		File tempFile = util.getTempFile(originalFile);

		encryptFile(
			originalFile.getAbsolutePath(),
			tempFile.getAbsolutePath(),
			aliases,
			password);

		if (!util.delete(originalFile))
			throw new IOException(
				"Couldn't overwrite " + originalFile.getAbsolutePath());
		if (!util.rename(tempFile, originalFile))
			throw new IOException(
				"Couldn't rename "
					+ tempFile.getAbsolutePath()
					+ " to "
					+ originalFile.getAbsolutePath());
	}

	/**
	 * This method retrieves a key or keys for a particular
	 * alias and writes the information to the specified
	 * OutputStream.
	 * 
	 * @param alias the alias for which keys should be saved
	 * @param secret if true, include secret keys
	 * @param passphrase if secret keys are to be included, the
	 * passphrase must be passed here
	 */
	private void exportKeys(
			OutputStream os,
			String alias,
			boolean secret,
			byte[] passphrase)
			throws KeyStoreException, IOException, UnrecoverableKeyException
	{
		Key publicKey = getKms().getPublicKey(alias, null);
		if (publicKey == null)
			throw new KeyStoreException("No public key for " + alias);
		if (secret)
		{
			if (passphrase == null)
				throw new UnrecoverableKeyException("Passphrase is null");
			Key privateKey = getKms().getPrivateKey(alias, passphrase);
			privateKey.encryptSecretKeyMaterial(
				passphrase,
				PgpConstants.CIPHER_3DES,
				S2kAlgorithm.S2K_TYPE_ITERATED_AND_SALTED,
				PgpConstants.HASH_SHA1,
				65536,
				true);
			Keyring privateKeyring = new Keyring();
			privateKeyring.addKey(privateKey);
			privateKeyring.save(os, true, true);
			// Remove the passphrase on the secret key, or it will
			// interfere if there is a passphrase change this session.
			// The Hush key server does not use the passphrases on the
			// secret key, it puts the secret key in an encrypted pgp
			// message - sbs
			privateKey.encryptSecretKeyMaterial(null, 0, 0, 0, 0, true);
		}
		Keyring publicKeyring = new Keyring();
		publicKeyring.addKey(publicKey);
		publicKeyring.save(os, true, false);
	}
	
	/**
	 * This method retrieves a key or keys for a particular
	 * alias and returns a String.
	 * 
	 * @param alias the alias for which keys should be saved
	 * @param secret if true, include secret keys
	 * @param passphrase if secret keys are to be included, the
	 * passphrase must be passed here
	 * @return the key or keys
	 */	
	public String exportKeysToString(String alias,
			boolean secret,
			byte[] passphrase)
			throws KeyStoreException, IOException, UnrecoverableKeyException
	{
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		this.exportKeys(baos, alias, secret, passphrase);
		baos.close();
		return Conversions.byteArrayToString(baos.toByteArray(), UTF8);
	}
	
	/**
	 * This method saves a key or keys for a particular
	 * alias to a file.
	 * 
	 * @param filepath the full path to the file to store the keys
	 * @param alias the alias for which keys should be saved
	 * @param secret if true, include secret keys
	 * @param passphrase if secret keys are to be included, the
	 * passphrase must be passed here
	 */
	public void exportKeysToFile(
		String filepath,
		String alias,
		boolean secret,
		byte[] passphrase)
		throws KeyStoreException, IOException, UnrecoverableKeyException
	{
		FileUtilities fileUtils = new FileUtilities();
		FileOutputStream outputFile = fileUtils.getFileOutputStream(new File(filepath));
		this.exportKeys(outputFile, alias, secret, passphrase);
		outputFile.close();
	}

	public void finalize()
	{
		Logger.log(this, Logger.DEBUG, "Finalizing engine");
		if (randomSeedUpdateThread != null)
			randomSeedUpdateThread.stop();
		if ( ! randomSeedUpdateOnFinalize ) return;
		try
		{
			if (getAlias() != null)
			{
				getKms().saveRandomSeed(getAlias(), null);
				Logger.log(this, Logger.DEBUG, "Random seed saved during finalization");
			}
		}
		catch (Throwable t)
		{
			Logger.logThrowable(this, Logger.WARNING, "Caught throwable while saving random seed", t);
		}
	}

	/**
	 *	This method is used to finish the verification process started in various methods.
	 *
	 *	It is important because it defines policy for returning signature verification results.
	 *
	 *  
	 */
	protected int finishSignatureVerification(String signer, Signature[] sigs, Vector validSigners, Vector invalidSigners)
		throws KeyStoreException, IOException
	{
		if ( sigs.length == 0 ) return NO_SIGNATURE_FOUND;
		int returnValue = SIGNATURE_VALID;
		if ( validSigners == null ) validSigners = new Vector();
		else validSigners.removeAllElements();
		if ( invalidSigners == null ) invalidSigners = new Vector();
		else invalidSigners.removeAllElements();
		for (int z = 0; z < sigs.length; z++)
		{
			Key thisKey = getSignerKey(signer, sigs[z]);
			if (thisKey == null)
			{
				invalidSigners.addElement("Unknown signer");
				returnValue = NO_CERTIFICATE_FOUND;
			}
			else
			{
				try
				{
					String[] certifiedAliases = getKms().getCertifiedAliases(
							thisKey, sigs[z].getCreationTime(true));
					try
					{
						sigs[z].finishVerification(thisKey);
						getKms().checkCertificate(thisKey,
								sigs[z].getCreationTime(true));
						for (int a = 0; validSigners != null
								&& a < certifiedAliases.length; a++)
							validSigners.addElement(certifiedAliases[a]);
					}
					catch (InvalidSignatureException e)
					{
						for (int a = 0; invalidSigners != null
								&& a < certifiedAliases.length; a++)
							invalidSigners.addElement(certifiedAliases[a]);
						if (returnValue != NO_CERTIFICATE_FOUND)
							returnValue = SIGNATURE_INVALID;
					}

				}
				catch (KeyStoreException e)
				{
					Logger.logThrowable(this, Logger.WARNING,
							"Exception when checking signature", e);
				}
				catch (InvalidSignatureException e)
				{
					Logger.logThrowable(this, Logger.WARNING,
							"Exception when checking signature", e);
				}
			}
		}
		return returnValue;
	}
	
	public byte[] generateMessageDigest(byte[] input, String algorithm)
	{
		Digest digest = null;
		if ( algorithm == null ) throw new IllegalArgumentException(
				"Algorithm cannot be null");
		algorithm = algorithm.trim().toUpperCase();
		for (int x=0; x<PgpConstants.HASH_STRINGS.length; x++)
		{
			if ( algorithm.equals(PgpConstants.HASH_STRINGS[x]) )
			{
				digest = AlgorithmFactory.getDigest(x);
				break;
			}
		}
		if ( digest == null ) throw new IllegalArgumentException(
				"No digest implementation found for: " + algorithm);
		byte[] output = new byte[digest.getDigestSize()];
		digest.update(input, 0, input.length);
		digest.doFinal(output, 0);
		return output;
	}
	
	/**
	 * Generate a strong random password. To be used in conjunction with the
	 * passwordEncryptFile() method. Generate a random password, encrypt a file
	 * with it, and then public key encrypt the password.  Then, in order to
	 * share the file with new recipients, it is only necessary to re-encrypt
	 * the password, not the entire file.
	 * 
	 * @return the password
	 */
	public String generatePassword()
	{
		updateRandom(new Object[0]);
		byte[] passphrase = new byte[32];
		getKms().getRandom().nextBytes(passphrase);

		return Conversions.bytesToHexString(passphrase);
	}

	/**
	 * Generate a password or unique id which matches the specified pattern.
	 * Patterns can include A or a, which will be replaced with a randomly
	 * selected letter (in the case specified), a #, which will be replaced
	 * with an integer between 0 and 9, or any other character which
	 * will be left as is. 
	 * @param pattern The pattern for the password to match
	 * @param exclude Any characters that should be excluded
	 * @return
	 */
	private String generatePassword(String pattern, char[] exclude)
	{
		StringBuffer password = new StringBuffer();
		for (int i = 0; i < pattern.length(); i++)
		{
			char c = pattern.charAt(i);

			if (c == '#' || c == 'A' || c == 'a')
			{
				int start = 0;
				int count = 0;
				if (c == '#')
				{
					start = 48;
					count = 10;
				}
				else if (c == 'A')
				{
					start = 65;
					count = 26;
				}
				else if (c == 'a')
				{
					start = 97;
					count = 26;
				}
				
				do
				{
					c = (char)((Math.abs(getKms().getRandom().nextInt()) % count) + start);
				}
				while (ArrayTools.contains(exclude, c));

			}
			password.append(c);
		}
		return password.toString();
	}

	/**
	 * A method to retrieve the identity of the currently authenticated user
	 * 
	 * @return The currently authenticated alias, or null if no authentication
	 *         has been performed
	 */
	public String getAlias()
	{
		return authenticatedAlias;
	}

	/**
     * Returns whether the message is set to anonymous.
     * 
     * Setting this property affects only non-SecureMessage methods.
	 * SecureMessage methods ignore this property and use the corresponding
	 * property on SecureMessage.
     * 
     * @return
     */
    public boolean getAnonymous()
    {
        return anonymous;
    }
    
    protected boolean getCachePasswords()
    {
    	return cachePasswords;	
    }

	/**
	 * Retrieve the current customer ID.
	 * 
	 * @return the current customer ID, a 32 character string
	 */
	public String getCustomerID()
	{
		return kms.getCustomerID();
	}

	/**
     * Convenience function for converting aliases and certificates as strings
     * or byte arrays into a usable array of keys.
     * 
     * @param aliases
     *            a Vector of aliases, as Strings
     * @param certificates
     *            a Vector of certificates, as strings or byte arrays
     * @return a usuable array of keys
     * @throws MissingSelfSignatureException
     * @throws InvalidSignatureException
     * @throws IOException
     * @throws KeyStoreException
     */
    protected Key[] getKeys(String[] aliases, String[] certificates)
            throws InvalidSignatureException, MissingSelfSignatureException,
            KeyStoreException, IOException
    {
        updateRandom(new Object[]
        { aliases, certificates });
        if (certificates == null)
        {
            certificates = new String[0];
        }

        if (aliases == null)
        {
            aliases = new String[0];
        }

        Keyring keyring = new Keyring();

        for (int x = 0; x < certificates.length; x++)
        {
            byte[] certBytes = null;
            Object certObj = certificates[x];
            if (certObj instanceof String)
                certBytes = Conversions.stringToByteArray((String) certObj,
                        UTF8);
            else if (certObj instanceof byte[])
                certBytes = (byte[]) certObj;
            else
                throw new KeyStoreException("Couldn't decode certificate");
            keyring.load(new ByteArrayInputStream(certBytes));
        }

        Key[] extraKeys = keyring.getKeys(null);
        
        Vector keyVector;
        if ( extraKeys == null ) keyVector = new Vector();
        else keyVector = Conversions2.arrayToVector(extraKeys);

        for (int x = 0; x < aliases.length; x++)
		{
			Key thisKey = getKms().getPublicKey((String) aliases[x], null);
			if (thisKey != null)
			{
				getKms().checkCertificate(thisKey,
						System.currentTimeMillis() / 1000);
				keyVector.addElement(thisKey);
			}
		}

        Key[] keys = new Key[keyVector.size()];
        keyVector.copyInto(keys);
        return keys;
    }
	
	/**
	 * A method to return login credentials stored on the Hush Key Server
	 * Network for the currently authenticated alias.
	 * 
	 * @return a Vector containing String values as follows: username, password,
	 *         hostname
	 */
	public Vector getLoginCredentials() throws IOException, KeyStoreException
	{
		updateRandom(new Object[0]);
		checkAuthentication();
		if (loginCredentials != null)
		{
			return loginCredentials;
		}

		MailServerInformation info = getKeyserverImplementation().getMailServerInformation(authenticatedAlias);
		
		Vector loginCredentials = new Vector();
		
		loginCredentials.addElement(info.getEmailUsername());
		loginCredentials.addElement(Conversions.byteArrayToString(decrypt(
				Conversions.stringToByteArray(info.getEncryptedEmailPassword(),
						UTF8), null), UTF8));
		loginCredentials.addElement(info.getEmailHostname());
		this.loginCredentials = loginCredentials;
		return loginCredentials;
	}

	/**
	 * Returns parameters defined by this applet.
	 * 
	 * @return an array of descriptions of the receiver's parameters
	 */
	public static final String[][] getParameterInfo()
	{
		return parameterInfo;
	}

	public static final String getVersionAsString()
	{
		return HushEncryptionEngineCore.ENGINE_VERSION[0] + "."
		+ HushEncryptionEngineCore.ENGINE_VERSION[1] + "."
		+ HushEncryptionEngineCore.ENGINE_VERSION[2] + "."
		+ HushEncryptionEngineCore.ENGINE_VERSION[3];
	}
	
	public static final long getVersionAsLong()
	{
		return (HushEncryptionEngineCore.ENGINE_VERSION[0] << 24)
				| (HushEncryptionEngineCore.ENGINE_VERSION[1] << 16)
				| (HushEncryptionEngineCore.ENGINE_VERSION[2] << 8)
				| HushEncryptionEngineCore.ENGINE_VERSION[3];
	}
	
	/**
	 * Returns the passphrase expiration time that is stored for this key in
	 * seconds since 1970-01-01 00:00:00 UTC, or -1 if there is no passphrase
	 * expiration time.
	 */
	public long getPassphraseExpirationTime(String alias)
		throws KeyStoreException
	{
		updateRandom(new Object[] { alias });
		checkAuthentication();
		Date time = getKeyserverImplementation().getPassphraseExpirationTime(alias);
		if (time == null)
			return 0;
		return time.getTime() / 1000;
	}
	
	public boolean isPassphraseExpired()
		throws KeyStoreException
	{
		checkAuthentication();
		return getPassphraseExpirationTime(getAlias()) < (System.currentTimeMillis() / 1000);
	}
	
	/**
	 * Returns the last access time for the private key in seconds
	 * since 1970-01-01 00:00:00 GMT.
	 * 
	 * @return the last access time
	 */
	public long getPrivateKeyLastAccessTime()
	{
		updateRandom(new Object[0]);
		checkAuthentication();
		try
		{
			return getKms().retrievePrivateKeyRecord(
				getAlias(),
				null).lastAccessTime;
		}
		catch (KeyStoreException e)
		{
			throw ExceptionWrapper
					.wrapInRuntimeException("Keystore exception (account may be deactivated)", e);
		}
		catch (IOException e)
		{
			throw ExceptionWrapper
					.wrapInRuntimeException("Exception that should never happen", e);
		}
	}

	/**
	 * Returns the PRNG in use by the KMS.
	 * 
	 * @return the PRNG
	 */
	public SecureRandom getSecureRandom()
	{
		return getSecureRandomCallback().getSecureRandom();
	}
	
	private SecureRandomCallback getSecureRandomCallback()
	{
		if ( secureRandomCallback == null )
		{
			setSecureRandom(new SecureRandom());
		}
		return secureRandomCallback;
	}
	
	public void setSecureRandom(SecureRandom random)
	{
		final SecureRandom finalRandom = random;
		setSecureRandomCallback(new SecureRandomCallback()
		{

			public SecureRandom getSecureRandom()
			{
				return finalRandom;
			}
		});
	}
	
	/**
	 * Given the signer and a signature returns a key to use for verification.
	 * Signer totally overrides signature.  If signer is null, the key ID from the
	 * signature is used to retrieve the key.
	 * 
	 * @param signer
	 * @param signature
	 * @return the verification key
	 */
	protected Key getSignerKey(String signer, Signature signature)
		throws IOException, KeyStoreException
	{
		return (signer == null || "".equals(signer.trim()) )
					? getKms().getPublicKey(
						null,
						Conversions.bytesToHexString(
							signature.getIssuerKeyID(false)))
					: getKms().getPublicKey(signer, Conversions.bytesToHexString(
							signature.getIssuerKeyID(false)));
	}

	public void setParameter(String name, String value)
	{
		try
		{
			PropertyDescriptor myProperty = null;
			for (int x = 0; x < propertyDescriptors.length; x++)
			{
				if (propertyDescriptors[x].getName().equals(name))
				{
					myProperty = propertyDescriptors[x];
					break;
				}
			}
			if (myProperty == null)
				throw new RuntimeException("Design error, property not found: "
						+ name);
			Object myValue = null;
			Class type = myProperty.getPropertyType();
			if (String.class.equals(type))
			{
				myValue = value;
			}
			else if (int.class.equals(type))
			{
				myValue = new Integer(value);
			}
			else if (long.class.equals(type))
			{
				myValue = new Long(value);
			}
			else if (boolean.class.equals(type))
			{
				myValue = new Boolean(value);
			}
			else if (String[].class.equals(type))
			{
				myValue = Conversions2.stringToArray(value, ",", false);
			}
			else
			{
				throw new RuntimeException("Design error, type not supported: "
						+ type.getName());
			}
			myProperty.getWriteMethod().invoke(this, new Object[]
			{ myValue });
		}
		catch (IllegalArgumentException e)
		{
			throw ExceptionWrapper.wrapInIllegalArgumentException(
					"Error setting parameter: " + name, e);
		}
		catch (IllegalAccessException e)
		{
			throw ExceptionWrapper.wrapInIllegalArgumentException(
					"Error setting parameter: " + name, e);
		}
		catch (InvocationTargetException e)
		{
			throw ExceptionWrapper.wrapInIllegalArgumentException(
					"Error setting parameter: " + name, e);
		}
	}
	
	public void setParametersFromParameterized(Parameterized table)
	{
		for(int x=0; x<parameterInfo.length; x++)
		{
			String value = table.getParameter(parameterInfo[x][0]);
			if ( value != null )
			{
				try
				{
					setParameter(parameterInfo[x][0], value);
				}
				catch(Throwable e)
				{
					Logger.log(this, Logger.ERROR, "Couldn't set parameter: " + parameterInfo[x][0] + "=" + value, e);			                                                      
				}
			}
		}
	}
	
	/**
	 * Inject randomness to the SecureRandom instance cached in KMS.
	 */
	public void injectEntropy(byte[] randomData)
	{
		getKms().getRandom().setSeed(randomData);
	}

	protected byte[] legacyHushmailDecryption(String input, Hashtable parameters)
		throws IOException, KeyStoreException
	{
		try
		{
			LegacyHushmail legacyHushmail = new LegacyHushmail();
			legacyHushmail.setParameters(parameters);
			legacyHushmail.setFormatted(input);
			legacyHushmail.decrypt(
				authenticatedAlias == null
					? null
					: getKms()
						.getPrivateKey(authenticatedAlias, null)
						.getEncryptionKey()
						.getSecretKey());
			return legacyHushmail.getPlainText();
			//Useful if we're dynamically loading classes, but
			// we aren't doing that now.  -sbs
			/*
			Class legacyHushmailClass =
				Class.forName("com.hush.hee.legacy.LegacyHushmail");
			
			Object legacyHushmail = legacyHushmailClass.newInstance();
			
			legacyHushmailClass
				.getMethod(
					"setParameters",
					new Class[] { Class.forName("java.util.Hashtable")})
				.invoke(legacyHushmail, new Object[] { parameters });
			
			legacyHushmailClass
				.getMethod(
					"setFormatted",
					new Class[] { Class.forName("java.lang.String")})
				.invoke(legacyHushmail, new Object[] { input });
			
			legacyHushmailClass
				.getMethod(
					"decrypt",
					new Class[] {
						Class.forName(
							"org.bouncycastle.crypto.CipherParameters")})
				.invoke(
					legacyHushmail,
					new Object[] {
						authenticatedAlias == null
							? null
							: getKms()
								.getPrivateKey(authenticatedAlias, null)
								.getEncryptionKey()
								.getSecretKey()});
			
			return (byte[]) legacyHushmailClass.getMethod(
				"getPlainText",
				null).invoke(
				legacyHushmail,
				null);
			*/
		}
		catch(KeyStoreException e)
		{
			throw e;
		}
		catch (Exception e)
		{
			throw LegacyDataFormatException.wrap(
					"Unable to decrypt old format Hushmail message", e);
		}
	}

	/**
	 * Construction of a random preactivation code.
	 * 
	 * @return java.lang.String
	 */
	private String makePreactivationCode()
	{
		String preactivationCodeHex = null;
		byte[] preactivationCode = new byte[preactivationCodeLength];
		getKms().getRandom().nextBytes(preactivationCode);
		preactivationCodeHex = Conversions.bytesToHexString(preactivationCode);

		return preactivationCodeHex;
	}

	/**
	 * Recover a passphrase. If the passphrase is split between the user, the
	 * customer and Hush, this method will recover a lost passphrase by
	 * supplying either the component held by the user or the customer.
	 * 
	 * @param alias java.lang.String Alias to recover passphrase for.
	 * @param component java.lang.String Hexencoded component supplied.
	 * @return String The passphrase recovered.
	 */
	public byte[] recoverPassphrase(String alias, String component)
		throws KeyStoreException
	{
		updateRandom(new Object[] { alias, component });
		checkAuthentication();
		alias = alias.toLowerCase().trim();
		byte[] binComponentFromNetwork = Conversions.hexStringToBytes(getKeyserverImplementation()
				.getPassphraseComponent(alias));
		byte[] binComponentFromUser = Conversions.hexStringToBytes(component);
		LineInterpolation alg = new LineInterpolation();
		alg.setEncodedShadow(binComponentFromUser);
		alg.setEncodedShadow(binComponentFromNetwork);
		byte[] res = alg.reconstruct();
		return res;
	}

	/**
	 * Retrieve the certificate for the specified alias.
	 * 
	 * @param alias the alias of the certificate owner
	 * @return the certificate as text
	 */
	public String retrieveCertificate(String alias)
		throws IOException, KeyStoreException
	{
		updateRandom(new Object[] { alias });
		alias = alias.toLowerCase().trim();

		Key c = getKms().getPublicKey(alias, null);

		if (c != null)
		{
			Keyring k = new Keyring();
			k.addKey(c);
			return k.toString();
		}
		else
		{
			return null;
		}
	}

	/**
	 * Given a certificate, retrieves a list of email addresses (aliases) found
	 * in the certificate.
	 * 
	 * @param certificate the certificate
	 * @return a Vector containing the String valued aliases found in the
	 *         certificate
	 * @throws CertificateException if the certificate cannot be parsed
	 */
	public Vector retrieveEmailAddressesFromCertificate(String certificate)
		throws
			InvalidSignatureException,
			MissingSelfSignatureException
	{
		try
		{
			updateRandom(new Object[] { certificate });
			Keyring keyring = new Keyring();
			keyring.setVerifySelfSignatures(false);
			keyring.load(new ByteArrayInputStream(Conversions.stringToByteArray(certificate, UTF8)));
			Vector toReturn = new Vector();
			Key[] keys = keyring.getKeys(null);
			for (int x = 0; x < keys.length; x++)
			{
				try
				{
					keys[x].verifySelfSignatures();
					UserID[] userIDs = keys[x].getUserIDs();
					for (int y = 0; y < userIDs.length; y++)
						toReturn.addElement(userIDs[y].toString());
				}
				catch (Throwable t)
				{
					Logger.logThrowable(this, Logger.WARNING, "Invalid key, skipping", t);
				}
			}
			return toReturn;
		}
		catch (IOException e)
		{
			throw ExceptionWrapper
					.wrapInRuntimeException("Exception that should never happen", e);
		}
	}

	/**
	 * Allows the user to select a location on the hard drive, and returns that
	 * location as a string.
	 * 
	 * @param filename The default filename
	 * @param prompt The prompt to display
	 * @return The complete path to the selected file
	 */
	public String selectFile(String filename, String prompt, int mode)
	{
		updateRandom(new Object[] { filename, prompt, new Integer(mode)});
		return new FileUtilities().selectFile(filename, prompt, mode);
	}

	public void sendFileToUrl(
			String url,
			final String filepath,
			final Vector aliases,
			final byte[] password,
			String fileParameterName,
			boolean sign,
			String signatureParameterName,
			Hashtable form,
			boolean forceEncrypt)
			throws IOException, KeyStoreException, MalformedURLException,
			NoEncryptionMethodException
		{
			sendFileToUrl(url, filepath, aliases, password,
					fileParameterName, form, -1, sign, signatureParameterName,
					forceEncrypt);
		}
	
	public void sendFileToUrl(
			String url,
			final String filepath,
			final Vector aliases,
			final byte[] password,
			String fileParameterName,
			Hashtable form,
			long sizeLimit,
			boolean sign,
			String signatureParameterName,
			boolean forceEncrypt)
			throws IOException, KeyStoreException, MalformedURLException,
			NoEncryptionMethodException
		{
			SecureMessage message = createSecureMessage();
			String[] aliasArray = null;
			if (aliases != null)
			{
				aliasArray = new String[aliases.size()];
				for (int i = 0; i < aliases.size(); i++)
				{
					aliasArray[i] = (String) aliases.elementAt(i);
				}
				message.setRecipientAliases(aliasArray);
			}
			if ( password != null )
				message.setPasswords(new byte[][]{password});
			sendFileToUrl(url, filepath, message, fileParameterName, form, sizeLimit,
					sign, signatureParameterName, forceEncrypt);
		}
	
	/**
	 * Uploads a file to a URL by HTTP POST, with the option of encryption.
	 * 
	 * @param url the URL to which the file will be posted
	 * @param filepath the path the the file to be uploaded
	 * @param aliases encrypt the file to these public keys (may be null)
	 * @param password encrypt the file with this password (may be null)
	 * @param fileParameterName the form variable in which the file will
	 *   be placed
	 * @param form parameters to POST
	 * @param sizeLimit the maximum size for a POST request
	 * @param sign sign the file with the current private key
	 * @param signatureParameterName the form variable in which the signature
	 *   will be placed
	 * @param forceEncrypt if neither aliases nor password are specified,
	 *   throw an exception (don't send plain text)
	 */
	public void sendFileToUrl(
		String url,
		final String filepath,
		SecureMessage message,
		String fileParameterName,
		Hashtable form,
		long sizeLimit,
		boolean sign,
		String signatureParameterName,
		boolean forceEncrypt)
		throws IOException, KeyStoreException, MalformedURLException,
		NoEncryptionMethodException
	{
		updateRandom(
			new Object[] {
				url,
				filepath,
				message,
				fileParameterName,
				form,
				new Long(sizeLimit),
				new Boolean(sign),
				signatureParameterName,
				new Boolean(forceEncrypt)});
		GenericIndicator myGenericIndicator = null;
		boolean encrypt =
			(message.getRecipientAliases() != null && message.getRecipientAliases().length > 0)
				|| (message.getPasswords() != null && message.getPasswords().length > 0);
		if (!encrypt && forceEncrypt)
		{
			throw new IllegalArgumentException("Attempt to encrypt without password or recipients specified");
		}
		FileInputStream fileInputStream = null;
		try
		{

			HttpRequest request =
				new HttpRequest(url, true, HttpRequest.MULTIPART_FORM_DATA);

			request.open();

			long fileSize = new FileUtilities().length(new File(filepath));

			if (useProgressIndicators)
			{
				myGenericIndicator = new GenericIndicator();
				myGenericIndicator.setSize(new Dimension(275, 75));
				myGenericIndicator.setTitle("Progress");

				if (encrypt)
				{
					myGenericIndicator.setFinishedText(
						"Encrypted. Now uploading.");
				}
				else
				{
					myGenericIndicator.setFinishedText(
						"Processed. Now uploading.");
				}

				myGenericIndicator.setVisible(true);
			}

			fileInputStream =
				new FileUtilities().getFileInputStream(
						new File(filepath));
			ProgressIndicatorInputStream inStream =
				new ProgressIndicatorInputStream(
					new BufferedInputStream(
						fileInputStream),
					(int) fileSize,
					myGenericIndicator);

			OutputStream outStream = request.getOutputStream();

			if (sizeLimit > 0)
				outStream = new ContentLengthOutputStream(outStream);

			outStream.write(Conversions.stringToByteArray("--" + request.getBoundary() + "\r\n", UTF8));
			outStream.write(Conversions.stringToByteArray(
				"Content-Disposition: form-data; name=\""
					+ fileParameterName
					+ "\"; filename=\""
					+ filepath
					+ "\"\r\n\r\n", UTF8));
			
			message.setInputStream(inStream);
			message.setOutputStream(outStream);
			if (usesArmor())
			{
				message.setUseArmor(true);
			}
			if (encrypt)
			{
				processSecureMessage(message, true, sign);
			}
			else if (sign)
			{
				generateSignatures(message);
			}
			else
			{
				byte[] buffer = new byte[2048];
				int x;
				while ((x = inStream.read(buffer)) != -1)
					outStream.write(buffer, 0, x);
			}
			
			if (sign && signatureParameterName != null)
			{
				String[] signatures = message.getOnePassSignatures();
				if (signatures.length > 1)
				{
					throw new RuntimeException(
						"Expected only a single signature to be generated.  Got "
							+ signatures.length);
				}
				if (form == null)
					form = new Hashtable();
				form.put(signatureParameterName, signatures[0]);
			}
				
			outStream.write(Conversions.stringToByteArray("\r\n", "UTF8"));

			if (form != null)
			{
				Enumeration enumeration = form.keys();

				while (enumeration.hasMoreElements())
				{
					// TODO: Encode these headers, like PEAR's Mail_mime does
					String key = (String) enumeration.nextElement();
					String value = (String) form.get(key);
					outStream.write(
						Conversions.stringToByteArray(
						"--" + request.getBoundary() + "\r\n", UTF8));
					outStream.write(
						Conversions.stringToByteArray(
						"Content-Disposition: form-data; name=\""
							+ key
							+ "\"\r\n\r\n", UTF8));
					outStream.write(Conversions.stringToByteArray(value, UTF8));
					outStream.write(Conversions.stringToByteArray("\r\n", "UTF8"));
				}
			}

			outStream.write(
					Conversions.stringToByteArray("--" + request.getBoundary() + "--\r\n", "UTF8"));
			
			if (sizeLimit > 0)
			{
				long contentLength =
					((ContentLengthOutputStream) outStream).getContentLength();
				if (contentLength > sizeLimit)
				{
					throw new IOException(
						"The size of the content after processing is "
							+ contentLength
							+ " bytes.  This exceeds the limit of "
							+ sizeLimit
							+ " bytes.");
				}
			}
			
			request.connect();

			inStream.close();

			if (request.getStatusCode() != HttpRequest.HTTP_OK)
				throw new IOException(
					"HTTP status: " + request.getStatusCode());
		}
		finally
		{
			try
			{
				if (myGenericIndicator != null)
					myGenericIndicator.setVisible(false);
			}
			catch(Exception e)
			{
			}
			try
			{
				if (fileInputStream != null) fileInputStream.close();
			}
			catch(Exception e)
			{
			}
		}
	}

	/**
	 * When anonymous is true, no identifying information will be placed in outgoing
	 * encrypted messages, so they are suitable for BCC-ed messages.
	 * 
	 * Setting this property affects only non-SecureMessage methods.
	 * SecureMessage methods ignore this property and use the corresponding
	 * property on SecureMessage.
	 * 
	 * @param anonymous true or false (defaults to false)
	 */
	public void setAnonymous(boolean anonymous)
	{
		this.anonymous = anonymous;
	}

	/**
	 * Set the customerID associated with requests. This is initially set by the
	 * CustomerID parameter, but may be changed.
	 *
	 * 
	 * @param customerID java.lang.String
	 */
	public void setCustomerID(String customerID)
	{
		updateRandom(new Object[] { customerID });
		kms.setCustomerID(customerID);
	}

	/**
	 * Sets the passphrase expiration time for the given alias in seconds
	 * since 1970-01-01 00:00:00 UTC.  Use -1 to set no expiration time.
	 */
	public void setPassphraseExpirationTime(String alias, long expirationTime)
		throws KeyStoreException
	{
		updateRandom(new Object[] { alias, new Long(expirationTime)});
		checkAuthentication();
		getKeyserverImplementation().savePassphraseExpirationTime(alias,
				expirationTime > 0 ? new Date(expirationTime * 1000) : null);
	}

	/**
	 * Perform the signing operation, generating signatures without modifying
	 * the output.  If getOutputStream() is not null, the unmodified message
	 * is written to that stream.  Otherwise, output is not written at all.
	 * <p>
	 * After completion, the onePassSignatures property on the SecureMessage
	 * will be populated.
	 * @param message The message to sign
	 */	
	public void generateSignatures(SecureMessage message)
			throws KeyStoreException, IOException
	{
		updateRandom(new Object[]{message});
		
		checkAuthentication();

		OutputStream outStream = message.getOutputStream();

		InputStream inStream = message.getInputStream();
		if (inStream == null)
		{
			inStream = new ByteArrayInputStream(
					message.getInputBytes());
		}
		
		Signature signature = new Signature();
		if ( signatureHashAlgorithm != -1 )
			signature.setHashAlgorithm(signatureHashAlgorithm);
		signature.startSigning(getKms().getPrivateKey(authenticatedAlias, null),
				PgpConstants.SIGNATURE_ON_BINARY_DOCUMENT);
		
		// Perform the signing operation
		byte[] b = new byte[2048];
		int x;
		while ((x = inStream.read(b)) != -1)
		{
			signature.update(b, 0, x);
			if ( outStream != null )
				outStream.write(b, 0, x);
		}
		inStream.close();	
		
		signature.finishSigning(getSecureRandom());
		
		setSignaturesOnMessage(message, new Signature[]{signature});
	}
	
	/**
	 * Perform the signing operation, with the output being a signed
	 * PGP Message
	 * <p>
	 * After completion, the onePassSignatures property on the SecureMessage
	 * will be populated.
	 * @param message The message to sign
	 */	
	public void sign(SecureMessage message) throws KeyStoreException, IOException
	{
		try
		{
			processSecureMessage(message, false, true);
		}
		finally
		{
			message.setOutputStream(null);
		}
	}
	
	private void setSignaturesOnMessage(SecureMessage message,
			Signature[] signatures)
	{
		if (signatures == null || signatures.length == 0)
			return;
		String[] signatureStrings = new String[signatures.length];
		for (int i = 0; i < signatures.length; i++)
		{
			signatureStrings[i] = signatures[i].toString(signatureHeaders);
		}
		message.setOnePassSignatures(signatureStrings);
	}
	
	/**
	 * Create a signature for the given data.
	 */
	public byte[] sign(byte[] toSign) throws KeyStoreException
	{
		SecureMessage message = createSecureMessage();
		message.setInputBytes(toSign);
		try
		{
			generateSignatures(message);
		}
		catch (IOException e)
		{
			ExceptionWrapper.wrapInIOException(
					"Should never get an IOException here", e);
		}
		return Conversions.stringToByteArray(message.getOnePassSignatures()[0],
				UTF8);
	}
	
	/**
	 * Generates a signature for the file specified.  Authentication must be
	 * performed first.
	 * 
	 * @param filename the full path to the file to sign
	 * @return the signature
	 */
	public byte[] signFile(String filename) throws IOException, KeyStoreException
	{
		InputStream fileStream =
			new FileUtilities().getFileInputStream(new File(filename));
		
		SecureMessage message = createSecureMessage();
		message.setInputStream(fileStream);
		generateSignatures(message);
		return Conversions.stringToByteArray(message.getOnePassSignatures()[0], UTF8);
	}

	/**
	 * Create a signature for the given data.
	 */
	public String signText(
		String text,
		String characterEncoding,
		boolean detached)
	{
		try
		{
			updateRandom(
				new Object[] { text, characterEncoding, new Boolean(detached)});
			checkAuthentication();
			CanonicalSignedMessage msg = new CanonicalSignedMessage();
			if ( signatureHashAlgorithm != -1 )
				msg.setHashAlgorithm(signatureHashAlgorithm);
			msg.setCharacterEncoding(characterEncoding);
			msg.setHeaders(signatureHeaders);
			msg.setText(text);
			msg.signMessage(
				getKms().getPrivateKey(getAlias(), null),
				kms.getRandom(),
				System.currentTimeMillis() / 1000);
			if (detached)
				return msg.getArmoredSignatures();
			return msg.getSignedMessage();
		}
		catch (KeyStoreException e)
		{
			throw ExceptionWrapper
					.wrapInRuntimeException("Keystore exception (account may be deactivated)", e);
		}
		catch (IOException e)
		{
			throw ExceptionWrapper
					.wrapInRuntimeException("Exception that should never happen", e);
		}
		catch (UnrecoverableKeyException e)
		{
			throw ExceptionWrapper
					.wrapInRuntimeException("Exception that should never happen", e);
		}
	}

	public byte[] signText(
			byte[] text,
			String characterEncoding,
			boolean detached)
			throws UnsupportedEncodingException
	{
		return Conversions.stringToByteArray(signText(
			Conversions.byteArrayToString(text, characterEncoding),
			characterEncoding, detached), characterEncoding);
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
		if (getKms() != null)
			getKms().updateRandom(input);
	}

	/**
	 * Uploads a certificate to the Hush Key Server Network.
	 * 
	 * @param cert the certificate to upload
	 * @param alias the alias to register the certificate under
	 * @param activationCode the code needed to activate and sign the certificate
	 * @return a String representing the alias registered.
	 */
	public String uploadCertificate(
		String certificate,
		String alias,
		String activationCode)
		throws
			KeyStoreException,
			IOException,
			MissingSelfSignatureException,
			InvalidSignatureException
	{
		updateRandom(new Object[] { certificate, alias, activationCode });
		alias = alias.toLowerCase().trim();
		return getKms().importCertificate(certificate, alias, activationCode);
	}

	/**
	 * Indicate whether or not the file encryption operations should use ASCII
	 * armoring.  ASCII armoring will base-64 encode the encrypted data and add
	 * headers and footers indicating the message type.  It will increase the
	 * size of the file, and reduce the speed of the encryption and decryption
	 * processes. ASCII armoring is off by default.
	 * 
	 * Setting this property affects only non-SecureMessage methods.
	 * SecureMessage methods ignore this property and use the corresponding
	 * property on SecureMessage.
	 * 
	 * @param useArmor true to turn armoring on, false to turn it off
	 */
	public void useArmor(boolean useArmor)
	{
		updateRandom(new Object[] { new Boolean(useArmor)});
		this.useArmor = useArmor;
	}

	/**
	 * Turn on or off graphical progress indicators.
	 * 
	 * @param on
	 */
	public void useProgressIndicators(boolean on)
	{
		updateRandom(new Object[] { new Boolean(on)});
		this.useProgressIndicators = on;
	}

	/**
	 * Indicates whether ASCII armoring for encryption to files is on or off.
	 * 
	 * Setting this property affects only non-SecureMessage methods.
	 * SecureMessage methods ignore this property and use the corresponding
	 * property on SecureMessage.
	 * 
	 * @return true if armoring is on, false if it is off
	 */
	public boolean usesArmor()
	{
		updateRandom(new Object[0]);
		return useArmor;
	}

	/**
	 * Verifies a signature against binary data read from a stream.
	 * 
	 * @param signer a specific signer to check the signature for, or
	 *  null to check all signatures [in]
	 * @param dataStream a stream to the data to verify [in]
	 * @param signature the signature to verify [in]
	 * @param validSigners a list of the verified signers [out]
	 * @param invalidSigners a list of signers whose
	 *    signatures did not verify [out]
	 * @return SIGNATURE_VALID, SIGNATURE_INVALID, or NO_CERTIFICATE_FOUND;
	 * NO_CERTIFICATE_FOUND will override SIGNATURE_INVALID
	 */
	public int verifyBinaryData(
		String signer,
		InputStream dataStream,
		String signature,
		Vector validSigners,
		Vector invalidSigners)
		throws IOException, DataFormatException, KeyStoreException
	{
		updateRandom(
			new Object[] {
				signer,
				dataStream,
				signature,
				validSigners,
				invalidSigners });

		Signature[] sigs =
			Signature.load(
				new ByteArrayInputStream(
					Conversions.stringToByteArray(signature, UTF8)));
		int x;
		byte[] b = new byte[2048];
		
		for (int z = 0; z < sigs.length; z++)
			sigs[z].startVerification();

		while ((x = dataStream.read(b)) != -1)
		{
			for (int z = 0; z < sigs.length; z++)
				sigs[z].update(b, 0, x);
		}

		dataStream.close();
		
		return finishSignatureVerification(signer, sigs, validSigners, invalidSigners);
	}

	public int verifyCleartextSignedMessage(String signer,
			String signedMessage, Vector validSigners,
			Vector invalidSigners, String[] content)
			throws IOException, DataFormatException, KeyStoreException
	{
		return verifyCleartextSignedMessage(signer, signedMessage,
				validSigners, invalidSigners, content, null);
	}
	
	/**
	 * Verifies a signature against a text string.  The string will be
	 * decoded using UTF-8 or the character encoding specified in
	 * the signature.
	 * 
	 * @param signer a specific signer to check the signature for, or
	 *  null to check all signatures [in]
	 * @param signedMessage the text and signature to verify [in]
	 * @param validSigners a list of the verified signers [out]
	 * @param invalidSigners a list of signers whose
	 *    signatures did not verify [out]
	 * @param content the text without the signature will
	 *  be placed in the first element of this array [out]
	 * @return SIGNATURE_VALID, SIGNATURE_INVALID, or NO_CERTIFICATE_FOUND;
	 * NO_CERTIFICATE_FOUND will override SIGNATURE_INVALID
	 */
	public int verifyCleartextSignedMessage(String signer,
			String signedMessage, Vector validSigners,
			Vector invalidSigners, String[] content,
			String characterEncoding)
			throws IOException, DataFormatException, KeyStoreException
	{
		updateRandom(new Object[]
		{ signer, signedMessage, validSigners, invalidSigners,
				content });
		CanonicalSignedMessage message = new CanonicalSignedMessage();
		if ( characterEncoding != null )
			message.setCharacterEncoding(characterEncoding);
		message.setSignedMessage(signedMessage);
		
		if (content != null && content.length > 0)
			content[0] = message.getText();

		Signature[] sigs = message.getSignatures();
		
		for (int z = 0; z < sigs.length; z++)
		{
			sigs[z].startVerification();
			sigs[z].update(message.getText());
		}

		return finishSignatureVerification(signer, sigs, validSigners, invalidSigners);	
	}

	public int verifyCleartextSignedMessage(String signer,
			byte[] signedMessage, Vector validSigners,
			Vector invalidSigners, byte[][] content,
			String characterEncoding) throws IOException, DataFormatException,
			KeyStoreException
	{
		String[] response = new String[]
		{ "" };
		int retVal = verifyCleartextSignedMessage(signer, Conversions
				.byteArrayToString(signedMessage, characterEncoding),
				validSigners, invalidSigners, response,
				characterEncoding);
		if (response != null && response.length > 0
				&& content != null
				&& content.length > 0)
			content[0] = Conversions.stringToByteArray(
					response[0], characterEncoding);
		return retVal;
	}
	
	/**
	 * Verifies a signature against a file stored on disk.
	 * 
	 * @param signer a specific signer to check the signature for, or
	 *  null to check all signatures [in]
	 * @param file the full path to the file to verify [in]
	 * @param signature the signature to verify [in]
	 * @param signersVector a list of the verified signers [out]
	 * @param validSigners a list of signers whose
	 *    signatures did not verify [out]
	 * @return SIGNATURE_VALID, SIGNATURE_INVALID, or NO_CERTIFICATE_FOUND;
	 * NO_CERTIFICATE_FOUND will override SIGNATURE_INVALID
	 */
	public int verifyFile(
		String signer,
		String file,
		String signature,
		Vector validSigners,
		Vector invalidSigners)
		throws DataFormatException, IOException, KeyStoreException
	{
		InputStream fileStream =
			new FileUtilities().getFileInputStream(new File(file));
		try
		{
			int result =
				verifyBinaryData(
					signer,
					fileStream,
					signature,
					validSigners,
					invalidSigners);
			fileStream.close();
			return result;
		}
		catch (DataFormatException e)
		{
			try
			{
				fileStream.close();
			}
			catch (Throwable t)
			{
			}
			throw e;
		}
		catch (IOException e)
		{
			try
			{
				fileStream.close();
			}
			catch (Throwable t)
			{
			}
			throw e;
		}
		catch (KeyStoreException e)
		{
			try
			{
				fileStream.close();
			}
			catch (Throwable t)
			{
			}
			throw e;
		}
	}

	/**
	 * Verifies a signature against a text string.  The string will be
	 * encoded for verification using UTF-8 or the character encoding
	 * specified in the signature headers.
	 * 
	 * @param signer a specific signer to check the signature for, or
	 *  null to check all signatures [in]
	 * @param file the text to verify [in]
	 * @param signature the signature to verify [in]
	 * @param validSigners a list of the verified signers [out]
	 * @param invalidSigners a list of signers whose
	 *    signatures did not verify [out]
	 * @return SIGNATURE_VALID, SIGNATURE_INVALID, or NO_CERTIFICATE_FOUND;
	 * NO_CERTIFICATE_FOUND will override SIGNATURE_INVALID
	 */
	public int verifyText(String signer, String text, String signature,
			Vector validSigners, Vector invalidSigners)
			throws IOException, DataFormatException, KeyStoreException
	{
		updateRandom(new Object[]
		{ signer, text, signature, validSigners, invalidSigners });

		Signature[] sigs = Signature.load(new ByteArrayInputStream(Conversions
				.stringToByteArray(signature, UTF8)));

		for (int z = 0; z < sigs.length; z++)
		{
			sigs[z].startVerification();
			sigs[z].update(text);
		}

		return finishSignatureVerification(signer, sigs, validSigners,
				invalidSigners);
	}
	
	public void setCachePasswords(boolean cachePasswords)
	{
		this.cachePasswords = cachePasswords;
	}
	
	public void setConnectTimeout(long timeoutMilliseconds)
	{
		setSystemProperty("sun.net.client.defaultConnectTimeout",
					timeoutMilliseconds);
	}

	public void setReadTimeout(long timeoutMilliseconds)
	{
		setSystemProperty("sun.net.client.defaultReadTimeout",
					timeoutMilliseconds);
	}
	
	public void setLogLevel(String logLevel)
	{
		try
		{
			Field levelField = Logger.class.getField(logLevel);
			Logger.setLogLevel(levelField.getInt(null));
		}
		catch(Exception e)
		{
			throw ExceptionWrapper.wrapInIllegalArgumentException(
					"Invalid log level", e);
		}	
	}
	
	private void setSystemProperty(final String property, final long value)
	{
		Strategy strategy = Strategy.createStrategy();
		// create a badge to perform the tasks requiring privileges
		Badge badge = new Badge()
		{
			public void invoke(Strategy strat)
			{
				Properties systemProperties = System.getProperties();

				systemProperties.put(property, String.valueOf(value));
				System.setProperties(systemProperties);
			}
		};
		strategy.handle(badge);
	}

	public void setNewEncryptionKeyAlgorithm(String newEncryptionKeyAlgorithm)
	{
		kms.setNewEncryptionKeyAlgorithm(newEncryptionKeyAlgorithm);
	}

	public void setNewEncryptionKeySize(int newEncryptionKeySize)
	{
		kms.setNewEncryptionKeySize(newEncryptionKeySize);
	}

	public void setNewKeySignatureHashAlgorithm(String newKeySignatureHashAlgorithm)
	{
		kms.setNewKeySignatureHashAlgorithm(newKeySignatureHashAlgorithm);
	}

	public void setNewKeySymmetricAlgorithm(String newKeySymmetricAlgorithm)
	{
		kms.setNewKeySymmetricAlgorithm(newKeySymmetricAlgorithm);
	}

	public void setNewPrivateAliasHashAlgorithm(String newPrivateAliasHashAlgorithm)
	{
		kms.setNewPrivateAliasHashAlgorithm(newPrivateAliasHashAlgorithm);
	}

	public void setNewPrivateAliasIterationCount(int newPrivateAliasIterationCount)
	{
		kms.setNewPrivateAliasIterationCount(newPrivateAliasIterationCount);
	}

	public void setNewSigningKeyAlgorithm(String newSigningKeyAlgorithm)
	{
		kms.setNewSigningKeyAlgorithm(newSigningKeyAlgorithm);
	}

	public void setNewSigningKeySize(int newSigningKeySize)
	{
		kms.setNewSigningKeySize(newSigningKeySize);
	}

	public void setSignatureHashAlgorithm(String signatureHashAlgorithm)
	{
		this.signatureHashAlgorithm =
			AlgorithmFactory.getHashID(signatureHashAlgorithm);
	}
	
	public void setEnableRSAKeyUpgrade(boolean enableRsaKeyUpgrade)
	{
		kms.setEnableRSAKeyUpgrade(enableRsaKeyUpgrade);
	}

	public void setSignPublicKeyLookupRequests(
			boolean signPublicKeyLookupRequests)
	{
		Logger.log(this, Logger.DEBUG, "Signing public key lookup requests: "
				+ signPublicKeyLookupRequests);
		if (getKeyserverImplementation() instanceof KeyserverClient)
		{
			((KeyserverClient) getKeyserverImplementation())
					.setSignPublicKeyLookupRequests(signPublicKeyLookupRequests);
		}
	}

	public void setPgpCertificateAuthorityCertificate(String certificate)
			throws IOException, InvalidSignatureException,
			MissingSelfSignatureException
	{
		Keyring keyring = Keyring.loadKeyring(certificate);
		Key[] keys = keyring.getKeys(null);
		if (keys.length != 1)
		{
			throw new IllegalArgumentException("CA must have exactly one key");
		}
		getKms().setCaCertificate(keys[0]);
	}
	
	public void setPgpMessageHeader(String header)
	{
		setPgpHeader(header, messageHeaders);
	}

	public void setPgpSignatureHeader(String header)
	{
		setPgpHeader(header, signatureHeaders);
	}
	
	private void setPgpHeader(String msgHeader, Hashtable messageHeaders)
	{ 
		if (msgHeader == null) return;
		msgHeader = msgHeader.trim();
		int colonIndex = msgHeader.indexOf(":");
		if (colonIndex > 1 && colonIndex < msgHeader.length() - 1)
		{
			messageHeaders.put(
				msgHeader.substring(0, colonIndex).trim(),
				msgHeader.substring(colonIndex + 1).trim());
		}
	}
	
	public void setRandomSeedUpdateCycle(int randomSeedUpdateCycle)
	{
		this.randomSeedUpdateCycle = randomSeedUpdateCycle;
	}
	
	public void setRandomSeedUpdateOnFinalize(boolean randomSeedUpdateOnFinalize)
	{
		this.randomSeedUpdateOnFinalize = randomSeedUpdateOnFinalize;
	}
	
	public void setForgiveBadRandomSeed(boolean forgiveBadRandomSeed)
	{
		getKms().setForgiveBadRandomSeed(forgiveBadRandomSeed);
	}
	
	public void setTestAlgorithms(boolean testAlgorithms)
	{
		if (testAlgorithms)
		{
			try
			{
				Class algorithmTests =
					Class.forName("com.hush.hee.AlgorithmTests");
				Method runTests = algorithmTests.getMethod("runTests", new Class[0]);
				runTests.invoke(null, new Object[0]);
			}
			catch (Throwable t)
			{
				Logger.logThrowable(this, Logger.ERROR, "Algorithm test failure", t);
				throw new RuntimeException(t.getMessage());
			}
		}
	}
	
	/**
	 * @deprecated
	 */
	public void setKeyserver(String[] keyservers)
	{
		setLookupKeyservers(keyservers);
		setUpdateKeyservers(keyservers);
	}
	
	public void setLookupKeyservers(String[] lookupKeyservers)
	{
		if (getKeyserverImplementation() instanceof KeyserverClient)
			((KeyserverClient) getKeyserverImplementation())
					.setLookupServerAddresses(lookupKeyservers);
	}

	public void setUpdateKeyservers(String[] updateKeyservers)
	{
		if (getKeyserverImplementation() instanceof KeyserverClient)
			((KeyserverClient) getKeyserverImplementation())
					.setUpdateServerAddresses(updateKeyservers);
	}

	public boolean getUseProgressIndicators()
	{
		return useProgressIndicators;
	}

	public void setUseProgressIndicators(boolean useProgressIndicators)
	{
		this.useProgressIndicators = useProgressIndicators;
	}
}