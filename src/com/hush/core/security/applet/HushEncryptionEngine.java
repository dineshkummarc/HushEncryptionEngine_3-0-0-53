/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.core.security.applet;

import java.applet.Applet;
import java.awt.Color;
import java.awt.Dimension;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.util.Hashtable;
import java.util.Properties;
import java.util.Vector;

import netscape.javascript.JSObject;

import com.hush.awt.EntropyCollectionFrame;
import com.hush.awt.event.EntropyCollectionCallback;
import com.hush.hee.HushEncryptionEngineCore;
import com.hush.hee.Parameterized;
import com.hush.core.security.applet.SecureMessage;
import com.hush.net.HttpRequest;
import com.hush.pgp.InvalidSignatureException;
import com.hush.pgp.Key;
import com.hush.pgp.Keyring;
import com.hush.pgp.MissingSelfSignatureException;
import com.hush.pgp.PgpConstants;
import com.hush.random.SHA1BlumBlumShubRandom;
import com.hush.util.Conversions;
import com.hush.util.Conversions2;
import com.hush.util.Logger;
import com.hush.util.UnrecoverableKeyException;

/**
 * This class provides the functionality of the Hush Encryption Engine in
 * a browser-based environment.
 * <p>
 * Many of the methods in this class utilize JavaScript callbacks.  These
 * methods can be identified by the parameters "onCompletionSuccess" and
 * "onCompletionFailure".  These method will exit after spawning off an
 * execution thread.  If and when the execution thread exits, a JavaScript
 * function will be called based on whether the operation was successful.
 * <p>
 * The JavaScript to be called can be submitted inline or by reference.
 * Inline functions are detected by having the key word 'function' as first
 * word. If an inline function is submitted, its body is evaluated as JavaScript
 * after replacing all occurences of certain key words with values.
 * <p>
 * Example: <code>"function {alert(\"Failed for PARAM_FILE with error: PARAM_FAILURE_REASON\");}"</code>
 * <p>
 * Referenced functions should be submitted by name and without parantheses
 * and semicolons. They must have a certain prototype of zero or more string
 * valued parameters.
 * <p>
 * Example: <code>"myFunction"</code>"
 * <p>
 * The parameters that are passed to the JavaScript functions are specified
 * in the documentation for the specific methods.
 * 
 */
public class HushEncryptionEngine
	extends Applet
	implements EntropyCollectionCallback, Parameterized, PgpConstants
{

	static
	{
		java.beans.Introspector.setBeanInfoSearchPath(new String[0]);
	}
	
	/**
	 * 
	 */
	private static final long serialVersionUID = -7951322348974205077L;

	/**
	 * @deprecated 
	 */
	public int BAD_PASSPHRASE = 1;

	private String characterEncoding = UTF8;

	/**
	 * @deprecated 
	 */
	public int ENCRYPTION_KEY_SIZE =
		HushEncryptionEngineCore.ENCRYPTION_KEY_SIZE;
	private String entropyCollectionCallback;

	/**
	 * @deprecated 
	 */
	public int ERROR = -1;
	private EntropyCollectionFrame frame;

	/**
	 * @deprecated 
	 */
	public int HTTP_GET = HushEncryptionEngineCore.HTTP_GET;

	/**
	 * @deprecated 
	 */
	public int HTTP_POST = HushEncryptionEngineCore.HTTP_POST;

	/**
	 * @deprecated 
	 */
	public int LOAD = HushEncryptionEngineCore.LOAD;

	/**
	 * Delegate all functionality to a HushEncryptionEngineCore object which
	 * does not derive from Applet.
	 */
	protected HushEncryptionEngineCore myDelegate = null;

	/**
	 * @deprecated 
	 */
	public int NO_CERTIFICATE_FOUND =
		HushEncryptionEngineCore.NO_CERTIFICATE_FOUND;

	/**
	 * @deprecated 
	 */
	public int NO_SIGNATURE_FOUND = HushEncryptionEngineCore.NO_SIGNATURE_FOUND;

	public final String PARAM_FAILURE_REASON = "PARAM_FAILURE_REASON";
	public final String PARAM_FILE = "PARAM_FILE";
	public final String PARAM_SIGNATURE_VERIFICATION_CODE =
		"PARAM_SIGNATURE_VERIFICATION_CODE";
	public final String PARAM_VERIFIED_SIGNERS = "PARAM_VERIFIED_SIGNERS";
	public final String PARAM_FAILED_SIGNERS = "PARAM_FAILED_SIGNERS";
	public final String PARAM_SIGNATURE = "PARAM_SIGNATURE";

	/**
	 * @deprecated 
	 */
	public int SAVE = HushEncryptionEngineCore.SAVE;

	private String[] shadows = null;

	/**
	 * @deprecated 
	 */
	public int SIGNATURE_INVALID = HushEncryptionEngineCore.SIGNATURE_INVALID;

	/**
	 * @deprecated 
	 */
	public int SIGNATURE_KEY_SIZE = HushEncryptionEngineCore.SIGNATURE_KEY_SIZE;

	/**
	 * @deprecated 
	 */
	public int SIGNATURE_VALID = HushEncryptionEngineCore.SIGNATURE_VALID;

	/**
	 * Stores a list of failures from the last signature verification.
	 */
	Vector signatureFailures;

	/**
	 * Stores a list of successes from the last signature verification.
	 */
	Vector signatureSuccesses;

	/**
	 * @deprecated 
	 */
	public int SUCCESS = HushEncryptionEngineCore.SUCCESS;

	/**
	 * A URL that will be accessed when the applet is stopped.  Useful
	 * for ensuring the end of sessions.
	 */
	private String onStopUrl = null;

	private long maximumPostRequestContentLength = -1;

	// SecureMessage hashtable for Opera, which can't pass the
	// messages back and forth to the applet
	private Hashtable answerSalts = new Hashtable();

	/**
	 * Attempt to authenticate to retrieve private keys and random seed data
	 * from the Hush Key Server Network.
	 * 
	 * @param alias The alias to attempt to authenticate.
	 * @param passphrase The passphrase for this alias
	 * @return SUCCESS, BAD_PASSPHRASE, or ERROR
	 */
	public int authenticate(String alias, String passphrase)
	{
		try
		{
			return myDelegate.authenticate(
				alias,
				Conversions.stringToByteArray(passphrase, UTF8));
		}
		catch (UnrecoverableKeyException e)
		{
			Logger.log(this, Logger.INFO,
				"Caught UnrecoverableKeyException - returning bad passphrase error");
			e.printStackTrace();
			return BAD_PASSPHRASE;
		}
		catch (Throwable t)
		{
			new JSException(t);
			return ERROR;
		}
	}

	/**
	 * Calls an inline JavaScript function through LiveConnect.
	 *
	 * @param function the inline function to call.
	 * @param parameters an array of parameters
	 * @param values an array of corresponding replacement values
	 */
	private void callJavascript(
		String jsfunction,
		String[] parameters,
		String[] values)
	{
		try
		{
			String evaluationString;

			// Find applet window.
			JSObject window = JSObject.getWindow(this);

			// Gets the applet frame window

			// Going to execute a javascript function. It can either be inline
			// or by reference.
			// If it starts with the key word 'function' it is assumed to be inline
			// and keywords should be replaced by parameters
			//
			// If it is not inline it is assumed to be a function with prototype
			// function(param1, param2 ...)
			if (isInline(jsfunction))
			{
				// Let the body of the function with parameters replaced with
				// parameter values.
				evaluationString =
					replace(
						stripMethodDefinition(jsfunction),
						parameters,
						values);
			}
			else
			{
				evaluationString = jsfunction + "(";

				for (int i = 0; i < values.length; i++)
				{
					evaluationString += ("\"" + jsEscape(values[i]) + "\"");

					if ((i + 1) < values.length)
					{
						evaluationString += ",";
					}
				}

				evaluationString += ");";
			}
			window.eval(evaluationString);
		}
		catch (Throwable t)
		{
			new JSException(t);
		}
	}

	public String canonicalizePassphrase(String passphrase)
	{
		try
		{
			return new String(myDelegate.canonicalizePassphrase(passphrase.toCharArray()));
		}
		catch (Throwable t)
		{
			new JSException(t);
		}
		return null;
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
	{
		try
		{
			myDelegate.changeLoginCredentials(
				oldPassword,
				newUsername,
				newPassword,
				newHostname);
		}
		catch (Throwable e)
		{
			new JSException(e);
		}
	}

	/**
	 * Attempt to change the passphrase of the given alias.
	 * 
	 * @param alias the alias to change the passphrase for.
	 * @param oldPassphrase the current passphrase for this alias.
	 * @param newPassphrase the new passphrase for this alias.
	 * @return SUCCESS, BAD_PASSWORD, or ERROR
	 */
	public int changePassphrase(
		String alias,
		String oldPassphrase,
		String newPassphrase)
	{
		// Attempt to change the passphrase for the given alias.
		try
		{
			shadows =
				myDelegate.changePassphrase(
					alias,
					Conversions.stringToByteArray(oldPassphrase, UTF8),
					Conversions.stringToByteArray(newPassphrase, UTF8));
			return SUCCESS;
		}
		catch (UnrecoverableKeyException e)
		{
			Logger.log(this, Logger.INFO,
				"Caught UnrecoverableKeyException - returning bad passphrase error");
			e.printStackTrace();
			return BAD_PASSPHRASE;
		}
		catch (Throwable t)
		{
			new JSException(t);
			return ERROR;
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
	{
		// Return whether or not the alias is available.
		try
		{
			return myDelegate.checkAliasAvailability(alias);
		}
		catch (Throwable t)
		{
			new JSException(t);
		}

		return false;
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
		try
		{
			return myDelegate.checkForCertificates(aliases);
		}
		catch (Throwable t)
		{
			new JSException(t);

			return new Vector();
		}
	}

	/**
	 * Checks to see if certificates are available for the aliases passed in the
	 * String.
	 * 
	 * @param aliases a list of aliases to check
	 * @param inSeparator the separator between the param aliases
	 * @param outSeparator the separator betweeen the aliases in the return value
	 * @return a comma-separated list of aliases for which no public keys were found
	 */
	public String checkForCertificates2(
		String aliases,
		String inSeparator,
		String outSeparator)
	{
		try
		{
			return Conversions2.vectorToString(
				myDelegate.checkForCertificates(
					Conversions2.stringToVector(aliases, inSeparator, false)),
				outSeparator);
		}
		catch (Throwable t)
		{
			new JSException(t);
			return Conversions2.vectorToString(
				Conversions2.stringToVector(aliases, inSeparator, false),
				outSeparator);
		}
	}

	/**
	 * Pops up an entropy collection panel with two lines of text. The entropy
	 * is used to seed or reseed a strong pseudo-random number generator.  This
	 * should ALWAYS be called before key generation. After entropy collection
	 * is completed, the JavaScript function specified by the
	 * "onEntropyCollectionCompleted" parameter is called.
	 * 
	 * @param amount the amount of entropy to collect in bytes
	 * @param text1 the first line of text to display in the panel
	 * @param text2 the second line of text to display in the panel
	 * @param sizeX the horizontal size of the panel in pixels
	 * @param sizeY the vertical size of the panel in pixels
	 * @param bgcolorR the R of the RGB color for the background
	 * @param bgcolorG the G of the RGB color for the background
	 * @param bgcolorB the B of the RGB color for the background
	 * @param textcolorR the R of the RGB color for the text
	 * @param textcolorG the G of the RGB color for the text
	 * @param textcolorB the B of the RGB color for the text
	 * @param fgcolorR the R of the RGB color for the foreground
	 * @param fgcolorG the G of the RGB color for the foreground
	 * @param fgcolorB the B of the RGB color for the foreground
	 * @param graphcolorR the R of the RGB color for the active parts of the graph
	 * @param graphcolorG the G of the RGB color for the active parts of the graph
	 * @param graphcolorB the B of the RGB color for the active parts of the graph
	 * @deprecated 
	 */
	public void collectEntropy(
		int amount,
		String text1,
		String text2,
		int sizeX,
		int sizeY,
		int bgcolorR,
		int bgcolorG,
		int bgcolorB,
		int textcolorR,
		int textcolorG,
		int textcolorB,
		int fgcolorR,
		int fgcolorG,
		int fgcolorB,
		int graphcolorR,
		int graphcolorG,
		int graphcolorB)
	{
		collectEntropy(
			amount,
			text1,
			text2,
			sizeX,
			sizeY,
			bgcolorR,
			bgcolorG,
			bgcolorB,
			textcolorR,
			textcolorG,
			textcolorB,
			fgcolorR,
			fgcolorG,
			fgcolorB,
			graphcolorR,
			graphcolorG,
			graphcolorB,
			getParameter("onEntropyCollectionCompleted"));
	}

	/**
	 * Pops up an entropy collection panel with two lines of text. The entropy
	 * is used to seed or reseed a strong pseudo-random number generator.  This
	 * should ALWAYS be called before key generation.
	 * 
	 * @param amount the amount of entropy to collect in bytes
	 * @param text1 the first line of text to display in the panel
	 * @param text2 the second line of text to display in the panel
	 * @param sizeX the horizontal size of the panel in pixels
	 * @param sizeY the vertical size of the panel in pixels
	 * @param bgcolorR the R of the RGB color for the background
	 * @param bgcolorG the G of the RGB color for the background
	 * @param bgcolorB the B of the RGB color for the background
	 * @param textcolorR the R of the RGB color for the text
	 * @param textcolorG the G of the RGB color for the text
	 * @param textcolorB the B of the RGB color for the text
	 * @param fgcolorR the R of the RGB color for the foreground
	 * @param fgcolorG the G of the RGB color for the foreground
	 * @param fgcolorB the B of the RGB color for the foreground
	 * @param graphcolorR the R of the RGB color for the active parts of the graph
	 * @param graphcolorG the G of the RGB color for the active parts of the graph
	 * @param graphcolorB the B of the RGB color for the active parts of the graph
	 * @param callback the JavaScript function to call when entropy collection
	 *        completes
	 */
	public void collectEntropy(
		int amount,
		String text1,
		String text2,
		int sizeX,
		int sizeY,
		int bgcolorR,
		int bgcolorG,
		int bgcolorB,
		int textcolorR,
		int textcolorG,
		int textcolorB,
		int fgcolorR,
		int fgcolorG,
		int fgcolorB,
		int graphcolorR,
		int graphcolorG,
		int graphcolorB,
		String callback)
	{
		entropyCollectionCallback = callback;
		frame =
			new EntropyCollectionFrame(
				myDelegate.getSecureRandom(),
				amount,
				new String[] { text1, text2 },
				this);
		frame.setInactiveColor(new Color(fgcolorR, fgcolorG, fgcolorB));
		frame.setActiveColor(new Color(graphcolorR, graphcolorG, graphcolorB));
		frame.setBackground(new Color(bgcolorR, bgcolorG, bgcolorB));
		frame.setSize(new Dimension(sizeX, sizeY));
		frame.paintAll(frame.getGraphics());
		frame.setVisible(true);
	}

	/**
	 * Asynchronously copy a URL to a file. Displays a file selection dialog.
	 * Supports decryption and signature verification.
	 * <p>
	 * Note: If accessing a script to retrieve a file, you can use the following
	 * format to force the filename to a name other than that of the script.
	 * "http://www.domain.com/test.cgi/filename.txt?key=value"
	 * <p>
	 * <i>Keywords for the JavaScript callbacks (see class documentation)</i>
	 * <br>
	 * Success: PARAM_FILE, PARAM_VERIFIED_SIGNERS, PARAM_FAILED_SIGNERS
	 * <br>
	 * Failure: PARAM_FILE, PARAM_FAILURE_REASON
	 * 
	 * @param url the URL to decrypt
	 * @param prompt the prompt to display in the file selection dialog
	 * @param defaultFilename the default filename for the file selection dialog
	 * @param password attempt to decrypt with this password (may be null)
	 * @param method GET or POST (0 or 1)
	 * @param form parameters to POST (ignored if method is not POST)
	 * @param decrypt try to decrypt the file with the private key and/or 
	 *   specified password
	 * @param signature verify the file against this signature; if unspecified
	 *   will still attempt to verify any signatures embedded in the file
	 * @param signerDelimiter when returning the lists of signers, separate
	 *   each entry with this string
	 * @param onCompletionSuccess JavaScript to execute on success
	 * @param onCompletionFailure JavaScript to execute on failure
	 */
	public void copyUrlToFile(
		final String url,
		final String prompt,
		final String defaultFilename,
		final String password,
		final Hashtable parameters,
		final int method,
		final Hashtable form,
		final boolean decrypt,
		final String signature,
		final String signerDelimiter,
		final String onCompletionSuccess,
		final String onCompletionFailure)
	{
		try
		{
			Thread copyThread = new Thread(new Runnable()
			{
				public void run()
				{
					Vector allVerifiedSigners = new Vector();
					Vector allFailedSigners = new Vector();
					String newFilepath = null;
					String filepath = null;
					try
					{
						filepath =
							myDelegate.selectFile(
								defaultFilename,
								prompt,
								SAVE);
						if (filepath == null)
							return;
						newFilepath =
							myDelegate.copyUrlToFile(
								url,
								filepath,
								password == null
									? null
									: Conversions.stringToByteArray(
										password,
										UTF8),
								parameters,
								method,
								form,
								decrypt,
								signature,
								allVerifiedSigners,
								allFailedSigners);
					}
					catch (Throwable t)
					{
						new JSException(t);

						// Handle failure
						callJavascript(
							onCompletionFailure,
							new String[] { PARAM_FILE, PARAM_FAILURE_REASON },
							new String[] { filepath, t.getMessage()});

						return;
					}

					// Handle success.
					callJavascript(
						onCompletionSuccess,
						new String[] {
							PARAM_FILE,
							PARAM_VERIFIED_SIGNERS,
							PARAM_FAILED_SIGNERS },
						new String[] {
							filepath,
							Conversions2.vectorToString(
								allVerifiedSigners,
								signerDelimiter),
							Conversions2.vectorToString(
								allFailedSigners,
								signerDelimiter)});
				}
			});
			copyThread.start();
		}
		catch (Throwable t)
		{
			new JSException(t);
		}
	}

	/**
	 * Asynchronously copy a URL to a file. Displays a file selection dialog.
	 * <p>
	 * Identical to copyUrlToFile, except that it accepts the form parameter
	 * as a String in the format of a properties file.
	 * 
	 * @param url the URL to decrypt
	 * @param prompt the prompt to display in the file selection dialog
	 * @param defaultFilename the default filename for the file selection dialog
	 * @param password attempt to decrypt with this password
	 * @param method GET or POST (0 or 1)
	 * @param form parameters to POST (ignored if method is not POST)
	 * @param decrypt try to decrypt the file with the private key and/or 
	 *   specified password
	 * @param signature verify the file against this signature; if unspecified
	 *   will still attempt to verify any signatures embedded in the file
	 * @param signerDelimiter when returning the lists of signers, separate
	 *   each entry with this string
	 * @param onCompletionSuccess JavaScript to execute on success
	 * @param onCompletionFailure JavaScript to execute on failure
	 */
	public void copyUrlToFile2(
		final String url,
		final String prompt,
		final String defaultFilename,
		final String password,
		String parameters,
		final int method,
		final String form,
		final boolean decrypt,
		final String signature,
		final String signerDelimiter,
		final String onCompletionSuccess,
		final String onCompletionFailure)
	{
		try
		{
			Properties formHashtable = new Properties();
			if (form != null)
				formHashtable.load(
					new ByteArrayInputStream(form.getBytes(UTF8)));
			Properties parametersHashtable = new Properties();
			if (parameters != null)
				parametersHashtable.load(
					new ByteArrayInputStream(parameters.getBytes(UTF8)));
			copyUrlToFile(
				url,
				prompt,
				defaultFilename,
				password,
				parametersHashtable,
				method,
				formHashtable,
				decrypt,
				signature,
				signerDelimiter,
				onCompletionSuccess,
				onCompletionFailure);
		}
		catch (Throwable t)
		{
			new JSException(t);
		}
	}

	/**
	 * Create an empty Hashtable object for use in scripting.  Elements can then
	 * be added to the Hashtable using the put() method.
	 * 
	 * @return an empty Hashtable
	 */
	public Hashtable createHashtable()
	{
		return new Hashtable();
	}

	/**
	 * This method should be called after collectEntropy to create keys for an
	 * alias and passphrase.
	 * 
	 * @param alias the alias to create keys for.
	 * @param passphrase the passphrase for this alias.
	 * @return boolean indicating whether or not key record creation was
	 *         successful.
	 */
	public boolean createKeyRecord(String alias, String passphrase)
	{
		return createKeyRecord(alias, passphrase, false, null);
	}

	/**
	 * This method should be called after collectEntropy to create keys for an
	 * alias and passphrase.
	 * 
	 * @param alias the alias to create keys for.
	 * @param passphrase the passphrase for this alias.
	 * @param useSharedSecret whether the passphrase should be split between
	 *        three parts.
	 * @return boolean indicating whether or not key record creation was
	 *         successful.
	 */
	public boolean createKeyRecord(
		String alias,
		String passphrase,
		boolean useSharedSecret)
	{
		return createKeyRecord(alias, passphrase, useSharedSecret, null);
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
	 * @return boolean indicating whether or not key record creation was
	 *         successful.
	 */
	public boolean createKeyRecord2(
		String alias,
		String passphrase,
		boolean useSharedSecret,
		String preActivationCode)
	{
		return createKeyRecord(
			alias,
			passphrase,
			useSharedSecret,
			preActivationCode);
	}

	public boolean createKeyRecord(
		String alias,
		String passphrase,
		boolean useSharedSecret,
		String preActivationCode)
	{
	    return createKeyRecord(alias, passphrase, useSharedSecret, preActivationCode, null);
	}

	public boolean createKeyRecord(String alias,
            String passphrase,
            boolean useSharedSecret,
            String preActivationCode,
            String encryptionMethod)
    {
        try
        {
            shadows =
                myDelegate.createKeyRecord(
                    alias,
                    Conversions.stringToByteArray(passphrase, UTF8),
                    useSharedSecret,
                    preActivationCode,
                    encryptionMethod);
            return true;
        }
        catch (Throwable e)
        {
            new JSException(e);
            return false;
        }       
    }
    
	/**
	 * Create an empty Vector object for use in scripting.  Elements can then be
	 * added to the Vector using the addElement() method. Mainly for use with
	 * the encryptText() and encryptFile() methods.
	 * 
	 * @return an empty Vector
	 */
	public Vector createVector()
	{
		return new Vector();
	}
	
	/**
	 * Create a new SecureMessage object for use in scripting.  The SecureMessage is then
	 * used to encrypt and sign data.
	 * 
	 * @return a new SecureMessage
	 */
	public SecureMessage createSecureMessage()
	{
		SecureMessage secureMessage = new SecureMessage();
		secureMessage.setCharacterEncoding(characterEncoding);
		return secureMessage;
	}
	
	/**
	 * Create a new QuestionAndAnswer object for use in scripting with the SecureMessage object.
	 * 
	 * @return a new QuestionAndAnswer
	 */
	public QuestionAndAnswer createQuestionAndAnswer()
	{
		return new QuestionAndAnswer();
	}

	/**
	 * Asynchronously decrypts a file directly on disk.  Displays a file
	 * selection dialog. The encrypted file is replaced with
	 * the decrypted content.  If authenticated, the private key will be used
	 * as well as the specified password (if not null).
	 * <p>
	 * <i>Keywords for the JavaScript callbacks (see class documentation)</i>
	 * <br>
	 * Success: PARAM_FILE
	 * <br>
	 * Failure: PARAM_FILE, PARAM_FAILURE_REASON
	 * 
	 * @param prompt the prompt to display in the file selection dialog
	 * @param password attempt to decrypt with this password (may be null)
	 * @param onCompletionSuccess JavaScript to execute on success
	 * @param onCompletionFailure JavaScript to execute on failure
	 */
	public void decryptFile(
		final String prompt,
		final String password,
		final String onCompletionSuccess,
		final String onCompletionFailure)
	{
		try
		{
			Thread decryptionThread = new Thread(new Runnable()
			{
				public void run()
				{
					String filepath = null;
					try
					{
						filepath = myDelegate.selectFile(null, prompt, LOAD);
						if (filepath == null)
							return;
						myDelegate.decryptFile(
							filepath,
							null,
							(password == null
								? null
								: password.getBytes(UTF8)));
					}
					catch (Throwable t)
					{
						new JSException(t);

						// Handle failure
						callJavascript(
							onCompletionFailure,
							new String[] { PARAM_FILE, PARAM_FAILURE_REASON },
							new String[] { filepath, t.getMessage()});

						return;
					}

					// Handle success.
					callJavascript(
						onCompletionSuccess,
						new String[] { PARAM_FILE },
						new String[] { filepath });
				}
			});
			decryptionThread.start();
		}
		catch (Throwable t)
		{
			new JSException(t);
		}
	}

	/**
	 * Decrypts a piece of text using the current private key.
	 * 
	 * @param encryptedText the encrypted text.
	 * @return the decrypted text.
	 */
	public String decryptText(String encryptedText)
	{
		try
		{
			return decryptText(encryptedText, new Hashtable());
		}
		catch (Throwable e)
		{
			new JSException(e);
		}

		return null;
	}

	/**
	 * Decrypts a piece of text using the current private key.
	 * 
	 * @param encryptedText the encrypted text.
	 * @param parameters decryption information required in special cases
	 * @return the decrypted text.
	 */
	public String decryptText(String encryptedText, Hashtable parameters)
	{
		try
		{
			byte[] decryptedBytes =
				myDelegate.decrypt(
					Conversions.stringToByteArray(encryptedText.trim(), UTF8),
					parameters);
			return new String(decryptedBytes, characterEncoding);
		}
		catch (Throwable e)
		{
			new JSException(e);
		}

		return null;
	}

	/**
	 * Decrypts a piece of text using the current private key.
	 * 
	 * @param encryptedText the encrypted text.
	 * @param parameters as a String that can be converted to a Properties file
	 * @return the decrypted text.
	 */
	public String decryptText2(String encryptedText, String parameters)
	{
		try
		{
			if (parameters == null)
				parameters = "";
			Properties p = new Properties();
			p.load(new ByteArrayInputStream(parameters.getBytes(UTF8)));
			return decryptText(encryptedText, p);
		}
		catch (Throwable e)
		{
			new JSException(e);
			return null;
		}
	}

	/**
	 * This method is called after entropy collection is completed.  It triggers
	 * a call to the JavaScript function specified in the
	 * "onEntropyCollectionCompleted" applet parameter.  It is required to
	 * completed the EntropyCollectionCallback interface, and should not be
	 * used by third-party developers.
	 */
	public void doCallback()
	{
		frame.setVisible(false);

		try
		{
			JSObject window = JSObject.getWindow(this);
			// Gets the applet frame window
			window.eval(entropyCollectionCallback);
		}
		catch (Throwable t)
		{
			new JSException(t);
		}
	}
	
	/**
	 *  Determine whether or not a SecureMessage can be encrypted
	 *  to its recipients, using the information provided by
	 *  setRecipientAliases and setQuestionsAndAnswers.  If a
	 *  recipient does not have an encryption method available
	 *  to it on the key server (public key or generated password),
	 *  and does not have a question and answer specified, it
	 *  will be returned in the String[].
	 *  
	 *  @param message the SecureMessage object with its recipients set
	 *  @return a comma separated String containing recipients for which an encryption
	 *  method is not available
	 */
	public String canEncrypt(SecureMessage message)
	{
		try
		{
			return Conversions2.stringArrayToString(myDelegate.canEncrypt(
                    message.getDelegate()), ",");
		}
		catch (Throwable t)
		{
			new JSException(t);
			return null;
		}
	}

	public String canEncryptWithQuestionAndAnswer(String recipientAliases,
			String question, String answer,
			String questionAndAnswerRecipientAliases)
	{
		try
		{
			SecureMessage secureMessage = buildSecureMessage(recipientAliases,
					question, answer, questionAndAnswerRecipientAliases,
					null, null);
			return Conversions2.stringArrayToString(myDelegate
					.canEncrypt(secureMessage.getDelegate()), ",");
		}
		catch (Throwable t)
		{
			new JSException(t);
			return null;
		}		
	}
	
	/**
	 * Asynchronously encrypts a file directly on disk.  Displays a file
	 * selection dialog. The encrypted file is replaced with
	 * the decrypted content.
	 * <p>
	 * <i>Keywords for the JavaScript callbacks (see class documentation)</i>
	 * <br>
	 * Success: PARAM_FILE
	 * <br>
	 * Failure: PARAM_FILE, PARAM_FAILURE_REASON
	 * 
	 * @param prompt the prompt to display in the file selection dialog
	 * @param aliases encrypt the file to these public keys (may be null)
	 * @param password encrypt the file with this password (may be null)
	 * @param onCompletionSuccess JavaScript to execute on success
	 * @param onCompletionFailure JavaScript to execute on failure
	 */
	public void encryptFile(
		final String prompt,
		final Vector aliases,
		final String password,
		final String onCompletionSuccess,
		final String onCompletionFailure)
	{
		// Create thread that calls password encrypt and then a javascript function.
		try
		{
			Thread encryptionThread = new Thread(new Runnable()
			{
				public void run()
				{
					String filepath = null;
					try
					{
						filepath = myDelegate.selectFile(null, prompt, LOAD);
						if (filepath == null)
							return;
						myDelegate.encryptFile(
							filepath,
							aliases,
							(password == null
								? null
								: password.getBytes(UTF8)));
					}
					catch (Throwable t)
					{
						new JSException(t);

						// Something went wrong, call the 'onCompleteFailure'
						callJavascript(
							onCompletionFailure,
							new String[] { PARAM_FILE, PARAM_FAILURE_REASON },
							new String[] { filepath, t.getMessage()});
						return;
					}

					try
					{
						callJavascript(
							onCompletionSuccess,
							new String[] { PARAM_FILE },
							new String[] { filepath });
					}
					catch (Throwable t)
					{
						new JSException(t);
						return;
					}
				}
			});

			encryptionThread.start();
		}
		catch (Throwable t)
		{
			new JSException(t);
		}
	}

	/**
	 * Attempt to encrypt the given text to the specified array of aliases.
	 * 
	 * @param text the text to encrypt.
	 * @param aliases the aliases to encrypt to.
	 * @return the encrypted text.
	 */
	public String encryptText(String text, Vector aliases)
	{
		return encryptText(text, aliases, new Vector());
	}

	/**
	 * Attempt to encrypt the given text to the specified arrays of aliases and certificates.
	 * 
	 * @param text the text to encrypt.
	 * @param aliases the aliases to encrypt to.
	 * @return the encrypted text.
	 */
	public String encryptText(String text, Vector aliases, Vector certificates)
	{
		try
		{
			byte[] textBytes =
				Conversions.stringToByteArray(text, characterEncoding);
			return Conversions.byteArrayToString(
				myDelegate.encrypt(textBytes, aliases, certificates),
				UTF8);
		}
		catch (Throwable t)
		{
			new JSException(t);
			return null;
		}
	}

	/**
	 * Attempt to encrypt a SecureMessage object.
	 * @param message the SecureMessage object.
	 */
	public void encryptSecureMessage(SecureMessage message)
	{
		try
		{
			myDelegate.encrypt(message.getDelegate());
		}
		catch (Throwable t)
		{
			new JSException(t);
		}
	}
	
	public String[] encryptWithQuestionAndAnswer(String inputText,
			String messageID,
			String recipientAliases, String question, String answer,
			String questionAndAnswerRecipientAliases)
	{
		try
		{
			SecureMessage message = buildSecureMessage(recipientAliases,
					question, answer,
					questionAndAnswerRecipientAliases, inputText,
					messageID);
			message.getDelegate().setUseArmor(true);
			myDelegate.encrypt(message.getDelegate());
			return new String[]{message.getOutputText(), message.getAuthInfo()};
		}
		catch (Throwable t)
		{
			new JSException(t);
			return null;
		}
	}

	/**
	 * Attempt to encrypt and sign a SecureMessage object.
	 * @param message the SecureMessage object.
	 */
	public void encryptAndSignSecureMessage(SecureMessage message)
	{
		try
		{
			myDelegate.encryptAndSign(message.getDelegate());
		}
		catch (Throwable t)
		{
			new JSException(t);
		}
	}

	/**
	 * Attempt to encrypt and sign a SecureMessage object.
	 * @param message the SecureMessage object.
	 */
	public String[] encryptAndSignWithQuestionAndAnswer(String inputText,
			String messageID,
			String recipientAliases, String question, String answer,
			String questionAndAnswerRecipientAliases)
	{
		try
		{
			SecureMessage message = buildSecureMessage(recipientAliases,
					question, answer,
					questionAndAnswerRecipientAliases, inputText,
					messageID);
			message.getDelegate().setUseArmor(true);
			myDelegate.encryptAndSign(message.getDelegate());
			return new String[]{message.getOutputText(), message.getAuthInfo()};
		}
		catch (Throwable t)
		{
			new JSException(t);
			return null;
		}
	}
	
	/**
	 * Asynchronously saves a key or keys for a particular
	 * alias to a file.
	 * <p>
	 * <i>Keywords for the JavaScript callbacks (see class documentation)</i>
	 * <br>
	 * Success: PARAM_FILE
	 * <br>
	 * Failure: PARAM_FILE, PARAM_FAILURE_REASON
	 * 
	 * @param prompt the prompt to display in the file selection dialog
	 * @param alias the alias for which keys should be saved
	 * @param secret if true, include secret keys
	 * @param passphrase if secret keys are to be included, the
	 * passphrase must be passed here
	 * @param onCompletionSuccess JavaScript to execute on success
	 * @param onCompletionFailure JavaScript to execute on failure
	 */
	public void exportKeysToFile(
		final String prompt,
		final String defaultFilename,
		final String alias,
		final boolean secret,
		final String passphrase,
		final String onCompletionSuccess,
		final String onCompletionFailure)
	{
		try
		{
			Thread exportThread = new Thread(new Runnable()
			{
				public void run()
				{
					String filepath = null;
					try
					{
						filepath =
							myDelegate.selectFile(
								defaultFilename,
								prompt,
								SAVE);
						if (filepath == null)
							return;
						myDelegate.exportKeysToFile(
							filepath,
							alias,
							secret,
							passphrase == null
								? null
								: Conversions.stringToByteArray(
									passphrase,
									UTF8));
					}
					catch (Throwable t)
					{
						new JSException(t);

						// Handle failure
						callJavascript(
							onCompletionFailure,
							new String[] { PARAM_FILE, PARAM_FAILURE_REASON },
							new String[] { filepath, t.getMessage()});

						return;
					}

					// Handle success.
					callJavascript(
						onCompletionSuccess,
						new String[] { PARAM_FILE },
						new String[] { filepath });
				}
			});
			exportThread.start();
		}
		catch (Throwable t)
		{
			new JSException(t);
		}
	}

	/**
	 * Attempt to encrypt the given text to the specified array of aliases.
	 * 
	 * @param text the text to encrypt.
	 * @param aliases the aliases to encrypt to.
	 * @param delimiter the delimiter that separates the aliases in the list.
	 * @return the encrypted text.
	 */
	public String encryptText2(String text, String aliases, String delimiter)
	{
		try
		{
			return encryptText(
				text,
				Conversions2.stringToVector(aliases, delimiter, false));
		}
		catch (Throwable e)
		{
			new JSException(e);
			return null;
		}
	}

		/**
	 * Attempt to encrypt the given text to the specified array of aliases.
	 * 
	 * @param text the text to encrypt.
	 * @param aliases the aliases to encrypt to.
	 * @param delimiter the delimiter that separates the aliases in the list.
	 * @return the encrypted text.
	 */
	public String encryptText3(String text, String aliases, String delimiter, String password)
	{
		try
		{
			byte[] textBytes =
				Conversions.stringToByteArray(text, characterEncoding);
			return Conversions.byteArrayToString(
				myDelegate.encrypt(textBytes, Conversions2.stringToVector(aliases, delimiter, false), null,
					( password == null || "".equals(password) ) ? null : new byte[][]{Conversions.stringToByteArray(password, UTF8)}),
				UTF8);
		}
		catch (Throwable t)
		{
			new JSException(t);
			return null;
		}
	}
	
	public String generateMessageDigest(String input, String algorithm)
	{
		try
		{
			return Conversions.bytesToHexString(
			myDelegate.generateMessageDigest(
			Conversions.stringToByteArray(input, characterEncoding),
			algorithm));
		}
		catch (Throwable t)
		{
			new JSException(t);
			return null;
		}
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
		try
		{
			return myDelegate.generatePassword();
		}
		catch (Throwable t)
		{
			new JSException(t);

			return null;
		}
	}

	/**
	 * A method to retrieve the identity of the currently authenticated user
	 * 
	 * @return The currently authenticated alias, or null if no authentication
	 *         has been performed
	 */
	public String getAlias()
	{
		return myDelegate.getAlias();
	}

	/**
	 * Returns information about this applet.
	 * 
	 * @return a string of information about this applet
	 */
	public String getAppletInfo()
	{
		return "HushEncryptionEngine\n"
			+ "\n"
			+ "Hush Communications, Ltd.\n"
			+ "Creation date: (16/03/2001 20:06:29)\n"
			+ "\n"
			+ "";
	}
	
	public String getVersionAsString()
	{
		return HushEncryptionEngineCore.getVersionAsString();
	}
	
	public long getVersionAsLong()
	{
		return HushEncryptionEngineCore.getVersionAsLong();
	}

	/**
	 * If the Sun Java Plug-in is run under IE, all attempts to access variables
	 * return null. (BIG IE/SunPlug-in bug, we think!).  So This method should
	 * always be used to access constacts.
	 * 
	 * @param constant The name of the constant
	 * @return the value of the constant
	 */
	public int getConstantInt(String constant)
	{
		try
		{
			if (constant.equals("SUCCESS"))
			{
				return SUCCESS;
			}

			if (constant.equals("BAD_PASSPHRASE"))
			{
				return BAD_PASSPHRASE;
			}

			if (constant.equals("ERROR"))
			{
				return ERROR;
			}

			if (constant.equals("SIGNATURE_VALID"))
			{
				return SIGNATURE_VALID;
			}

			if (constant.equals("SIGNATURE_INVALID"))
			{
				return SIGNATURE_INVALID;
			}

			if (constant.equals("NO_CERTIFICATE_FOUND"))
			{
				return NO_CERTIFICATE_FOUND;
			}

			if (constant.equals("NO_SIGNATURE_FOUND"))
			{
				return NO_SIGNATURE_FOUND;
			}

			if (constant.equals("SIGNATURE_KEY_SIZE"))
			{
				return SIGNATURE_KEY_SIZE;
			}

			if (constant.equals("ENCRYPTION_KEY_SIZE"))
			{
				return ENCRYPTION_KEY_SIZE;
			}

			if (constant.equals("SAVE"))
			{
				return SAVE;
			}

			if (constant.equals("LOAD"))
			{
				return LOAD;
			}

			if (constant.equals("HTTP_GET"))
			{
				return HTTP_GET;
			}

			if (constant.equals("HTTP_POST"))
			{
				return HTTP_POST;
			}

			throw new IllegalArgumentException("No such constant " + constant);
		}
		catch (Throwable t)
		{
			new JSException(t);
			return -99999999;
		}
	}

	/**
	 * Retrieve the current customer ID.
	 * 
	 * @return the current customer ID, a 32 character string
	 */
	public String getCustomerID()
	{
		return myDelegate.getCustomerID();
	}

	/**
	 * Returns a list of failed signers from the last signature verification.
	 *
	 * @param delimiter separates the signers in the list
	 * @return a list of failed signers
	 */
	public String getFailedSigners(String delimiter)
	{
		try
		{
			if (signatureFailures == null)
				return "";
			return Conversions2.vectorToString(signatureFailures, delimiter);
		}
		catch (Throwable t)
		{
			new JSException(t);
			return null;
		}
	}

	public String getJavaVendor()
	{
		return System.getProperty("java.vendor");
	}
	
	public String getJavaVersion()
	{
		return System.getProperty("java.version");
	}
	
	/**
	 * Determine if an error has occured in the applet since the last call to
	 * resetLastError() or getLastErrorMsg().  This should be called after
	 * every operation, since scripting allows for no exception handling.
	 * 
	 * @return true if an error has occured, false if no error has occured
	 */
	public boolean getLastError()
	{
		return JSException.getLastError();
	}

	/**
	 * Returns a string containing information on the last error to occur in the
	 * applet.
	 * 
	 * <p>
	 * This will reset stored error information, an getLastError() will return
	 * false until a new error occurs.
	 * </p>
	 * 
	 * @return the error description
	 */
	public String getLastErrorMsg()
	{
		return JSException.getLastErrorMsg();
	}

	/**
	 * A method to return login credentials stored on the Hush Key Server
	 * Network for the currently authenticated alias.
	 * 
	 * @return a Vector containing String values as follows: username, password,
	 *         hostname
	 */
	public Vector getLoginCredentials()
	{
		Vector response = new Vector();

		try
		{
			return myDelegate.getLoginCredentials();
		}
		catch (Throwable e)
		{
			new JSException(e);
			return null;
		}
	}

	/**
	* A method to return login credentials stored on the Hush Key Server
	* Network for the currently authenticated alias.
	* 
	* @return the hostname
	*/
	public String getLoginCredentialsHostname()
	{
		try
		{
			return (String) myDelegate.getLoginCredentials().elementAt(2);
		}
		catch (Throwable e)
		{
			new JSException(e);
			return null;
		}
	}

	/**
	* A method to return login credentials stored on the Hush Key Server
	* Network for the currently authenticated alias.
	* 
	* @return the password
	*/
	public String getLoginCredentialsPassword()
	{
		try
		{
			return (String) myDelegate.getLoginCredentials().elementAt(1);
		}
		catch (Throwable e)
		{
			new JSException(e);
			return null;
		}
	}

	/**
	 * A method to return login credentials stored on the Hush Key Server
	 * Network for the currently authenticated alias.
	 * 
	 * @return the username
	 */
	public String getLoginCredentialsUsername()
	{
		try
		{
			return (String) myDelegate.getLoginCredentials().elementAt(0);
		}
		catch (Throwable e)
		{
			new JSException(e);
			return null;
		}
	}

	/**
	 * Returns parameters defined by this applet.
	 * 
	 * @return an array of descriptions of the receiver's parameters
	 */
	public String[][] getParameterInfo()
	{
		String[][] info =
			{
				{
					"keyserver",
					"String",
					"Deprecated. The address of the default server on the Hush Key"
						+ " Server Network to which the applet should connect." },
				{
				"lookupKeyservers",
					"String",
					"Mandatory. Comma-separated list of the servers on the Hush Key"
						+ " Server Network to which the applet should connect for lookup"
						+ " (read-only) operations." },
					{
				"updateKeyservers",
					"String",
					"Mandatory. Comma-separated list of the servers on the Hush Key"
						+ " Server Network to which the applet should connect for update"
						+ " (write) operations." },
					{
				"connectTimeout",
					"int",
					"Optional. Java 1.4 and higher. A timeout for connections." },
					{
				"readTimeout",
					"int",
					"Optional. Java 1.4 and higher. A timeout for reads." },
					{
				"customerID",
					"String",
					"Mandatory. The customer ID for the domain on which you wish to"
						+ " create aliases." },
					{
				"onLoad",
					"String",
					"Mandatory. The JavaScript method that will be called when the"
						+ " applet is fully loaded." },
					{
				"onEntropyCollectionCompleted",
					"String",
					"Deprecated. The JavaScript method that will be called when entropy"
						+ " collection started by a call to collectEntropy(), is complete." },
					{
				"useProgressIndicators",
					"Optional. 'true' or 'false' indicating whether progress indicators"
						+ " should be displayed during streaming operations." },
					{
				"onStopUrl",
					"Optional.  Indicates a URL that will be accessed when the applet is stopped.  Useful for ending a session." }
		};

		return info;
	}

	/**
	 * Gets the expiration time for the passphrase associated
	 * with an alias.
	 *
	 * @param alias the alias to set
	 * @return the expiration time in seconds since 1970-01-01 00:00:00 UTC
	 */
	public long getPassphraseExpirationTime(String alias)
	{
		try
		{
			return myDelegate.getPassphraseExpirationTime(alias);
		}
		catch (Throwable e)
		{
			new JSException(e);
			return -1;
		}
	}

	/**
	 * Returns the last access time for the private key in seconds
	 * since 1970-01-01 00:00:00 GMT.
	 * 
	 * @return the last access time
	 */
	public long getPrivateKeyLastAccessTime()
	{
		return myDelegate.getPrivateKeyLastAccessTime();
	}

	/**
	 * Returns a list of verified signers from the last signature verification.
	 *
	 * @param delimiter separates the signers in the list
	 * @return a list of verified
	 */
	public String getVerifiedSigners(String delimiter)
	{
		try
		{
			if (signatureSuccesses == null)
				return "";
			return Conversions2.vectorToString(signatureSuccesses, delimiter);
		}
		catch (Throwable t)
		{
			new JSException(t);
			return null;
		}
	}

	/**
	 * Initializes the applet.
	 */
	public void init()
	{
		Logger.log(this, Logger.WARNING,
				"Initializing Hush Encryption Engine Version "
						+ HushEncryptionEngineCore.getVersionAsString());
		try
		{
			onStopUrl = getParameter("onStopUrl");
			myDelegate = new HushEncryptionEngineCore();
			myDelegate.init(this, new SHA1BlumBlumShubRandom());

			if ("true".equalsIgnoreCase(getParameter("useProgressIndicators")))
			{
				myDelegate.useProgressIndicators(true);
			}
		}
		catch (Throwable e)
		{
			new JSException(e);
		}
		try
		{
			JSObject window = JSObject.getWindow(this);
			// Gets the applet frame window
			window.eval(getParameter("onLoad"));
		}
		catch (Throwable t)
		{
			new JSException(t);
		}
	}

	/**
	 * Is the JavaScript parameter value an line JavaScript function or
	 * an actual JavaScript value.
	 * 
	 * @param the JavaScript that may or may not be an inline function
	 * @return true if it is an inline function
	 */
	private boolean isInline(String script)
	{
		if (script == null)
		{
			return false;
		}

		return script.trim().startsWith("function");
	}

	/**
	 * Replace any backslashes with double backslashes
		   * in a String.  (For JavaScript.)
	 * 
	 * @param s the original String
	 * @return the String with replacements made
	 */
	private String jsEscape(String s)
	{
		if (s == null)
			return null;

		StringBuffer result = new StringBuffer();

		for (int i = 0; i < s.length(); i++)
		{
			char c = s.charAt(i);

			switch (c)
			{
				case '\\' :
				case '"' :
					result.append('\\');
					result.append(c);
					break;
				case '\r' :
					result.append("\\r");
					break;
				case '\n' :
					result.append("\\n");
					break;
				default :
					result.append(c);
			}
		}

		return result.toString();
	}

	/**
	 * Decrypts a piece of text using the current private key or the
	 * given password.  (It tries both.)
	 * 
	 * Note: this expects the password to be in the same character encoding
	 * as the plain text of the message.
	 * 
	 * @param encryptedText the encrypted text.
	 * @param password the password for decryption.
	 * @return the decrypted text.
	 */
	public String passwordDecryptText(String encryptedText, String password)
	{
		try
		{
			byte[] decryptedBytes =
				myDelegate.decrypt(
					Conversions.stringToByteArray(encryptedText.trim(), UTF8),
					null,
					new byte[][] {
						 Conversions.stringToByteArray(
							password,
							characterEncoding)});
			return new String(decryptedBytes, characterEncoding);
		}
		catch (Throwable e)
		{
			new JSException(e);
		}

		return null;
	}

	/**
	 * Attempt to encrypt the given text to the specified password.
	 * <p>
	 * Note: this expects the text and password to be in the same
	 * character encoding.
	 * 
	 * @param text the text to encrypt.
	 * @param password the password for encryption.
	 * @return the encrypted text.
	 */
	public String passwordEncryptText(String text, String password)
	{
		try
		{
			byte[] textBytes =
				Conversions.stringToByteArray(text, characterEncoding);
			return Conversions.byteArrayToString(
				myDelegate.encrypt(
					textBytes,
					null, null,
					new byte[][] {
						 Conversions.stringToByteArray(
							password,
							characterEncoding)}),
				UTF8);
		}
		catch (Throwable t)
		{
			new JSException(t);
			return null;
		}
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
	public String recoverPassphrase(String alias, String component)
	{
		try
		{
			return Conversions.byteArrayToString(
				myDelegate.recoverPassphrase(alias, component),
				UTF8);
		}
		catch (Throwable t)
		{
			new JSException(t);

			return null;
		}
	}

	/**
	 * Replaces a series of parameters in a String with corresponding
	 * values.
	 *
	 * @param original the original String
	 * @param parameters an array of parameters
	 * @param values an array of replacement values
	 * @return the String with the parameters replaced by the values
	 */
	private String replace(
		String original,
		String[] parameters,
		String[] values)
	{
		if ((parameters == null)
			|| (values == null)
			|| (parameters.length != values.length))
		{
			throw new IllegalArgumentException("Parameter list and value list differ in length");
		}

		StringBuffer result = new StringBuffer();
		int last = 0;
		int pos = -1;
		int matchedParameter = -1;

		//   int leastPositive=-1
		int temp;

		do
		{
			pos = -1;

			// Find next a
			for (int i = 0; i < parameters.length; i++)
			{
				temp = original.indexOf(parameters[i], last);

				if ((temp >= 0) && (temp < pos || pos < 0))
				{
					matchedParameter = i;
					pos = temp;
				}
			}

			if (pos < 0)
			{
				// No more match, append rest of original.
				result.append(original.substring(last));
			}
			else
			{
				// append before parameter
				result.append(original.substring(last, pos));

				// append value
				result.append(jsEscape(values[matchedParameter]));

				//
				pos += parameters[matchedParameter].length();
			}

			last = pos;
		}
		while (pos > 0);

		return result.toString();
	}

	/**
	 * This will reset stored error information. A <code>getLastError()</code>
	 * will then return false until a new error occurs.
	 */
	public void resetLastError()
	{
		JSException.resetLastError();
	}

	/**
	 * Retrieve the certificate for the specified alias.
	 * 
	 * @param alias the alias of the certificate owner
	 * @return the certificate as text
	 */
	public String retrieveCertificate(String alias)
	{
		try
		{
			return myDelegate.retrieveCertificate(alias);
		}
		catch (Throwable e)
		{
			new JSException(e);
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
	 */
	public Vector retrieveEmailAddressesFromCertificate(String certificate)
	{
		try
		{
			return myDelegate.retrieveEmailAddressesFromCertificate(
				certificate);
		}
		catch (Throwable t)
		{
			new JSException(t);
			return null;
		}
	}

	/**
	 * Given a certificate, retrieves a list of email addresses (aliases) found
	 * in the certificate.
	 * 
	 * @param certificate the certificate
		   * @param separator the value the will separate the aliases in the
		   *  list returned.
	 * @return a String containing the aliases found in the
	 *         certificate
	 */
	public String retrieveEmailAddressesFromCertificate(
		String certificate,
		String separator)
	{
		try
		{
			return Conversions2.vectorToString(
				myDelegate.retrieveEmailAddressesFromCertificate(certificate),
				separator);
		}
		catch (Throwable t)
		{
			new JSException(t);
			return null;
		}
	}

	/**
	 * If a changePassphrase request involves splitting a passphrase into
	 * shadows, this returns the set of two shadows, either of which can be
	 * used in combination with one other shadow to reconstruct the passphrase.
	 * One shadow is stored on the Hush Key Server Network.
	 * 
	 * @return a Vector of String valued shadows, null if none were created
	 */
	public Vector retrieveShadows()
	{
		try
		{
			if (shadows == null)
				return null;
			Vector returnVector = new Vector();
			for (int x = 0; x < shadows.length; x++)
				returnVector.addElement(shadows[x]);
			return returnVector;
		}
		catch (Throwable t)
		{
			new JSException(t);
			return null;
		}
	}
	
    private void sendFileToUrlWithSecureMessagePrivate(
            final String url,
            final String prompt,
            final SecureMessage message,
            final String fileParameterName,
            final String filenameParameterName,
            Hashtable form,
            final boolean sign,
            final String signatureParameterName,
            final boolean forceEncrypt,
            final String onCompletionSuccess,
            final String onCompletionFailure)
        {
            // Create thread that calls encrypt and then a javascript function.
            try
            {
                if (form == null)
                    form = new Hashtable();
                
                final Hashtable finalForm = form;
            
                Thread sendThread = new Thread(new Runnable()
                {
                    public void run()
                    {
                        String filepath = null;
                        try
                        {
                            filepath = myDelegate.selectFile(null, prompt, LOAD);
                            if (filepath == null)
                                throw new RuntimeException("Upload cancelled");
                            if (filenameParameterName != null)
                            {
                                finalForm.put(
                                    filenameParameterName,
                                    new File(filepath).getName());
                            }
                            myDelegate.sendFileToUrl(
                                url,
                                filepath,
                                message.getDelegate(),
                                fileParameterName,
                                finalForm,
                                maximumPostRequestContentLength,
                                sign,
                                signatureParameterName,
                                forceEncrypt);
                        }
                        catch (Throwable t)
                        {
                            new JSException(t);

                            callJavascript(
                                onCompletionFailure,
                                new String[] { PARAM_FILE, PARAM_FAILURE_REASON },
                                new String[] { filepath, t.getMessage()});
                            return;
                        }
                        try
                        {
                            callJavascript(
                                onCompletionSuccess,
                                new String[] { PARAM_FILE },
                                new String[] { filepath });
                        }
                        catch (Throwable t)
                        {
                            new JSException(t);
                        }
                    }
                });
                sendThread.start();
            }
            catch (Throwable t)
            {
                new JSException(t);
            }
        }   
    
    
	/**
	 * Asynchronously copy a file to a URL. Displays a file selection dialog.
	 * Supports encryption and signing.
	 * <p>
	 * <i>Keywords for the JavaScript callbacks (see class documentation)</i>
	 * <br>
	 * Success: PARAM_FILE
	 * <br>
	 * Failure: PARAM_FILE, PARAM_FAILURE_REASON
	 * 
	 * @param url the URL to which the file will be posted
	 * @param prompt the prompt to display in the file selection dialog
	 * @param message the SecureMessage object to encrypt
	 * @param fileParameterName the form variable in which the file will
	 *   be placed
	 * @param filenameParameterName the form variable in which the file name
	 *   will be placed
	 * @param form parameters to POST (ignored if method is not POST)
	 * @param sign sign the file with the current private key
	 * @param signatureParameterName the form variable in which the signature
	 *   will be placed
	 * @param forceEncrypt if neither aliases nor password are specified,
	 *   throw an exception (don't send plain text)
	 * @param onCompletionSuccess JavaScript to execute on success
	 * @param onCompletionFailure JavaScript to execute on failure
	 */
	public void sendFileToUrlWithSecureMessage(
		final String url,
		final String prompt,
		final SecureMessage message,
		final String fileParameterName,
		final String filenameParameterName,
		String form,
		final boolean sign,
		final String signatureParameterName,
		final boolean forceEncrypt,
		final String onCompletionSuccess,
		final String onCompletionFailure)
	{
        // Create thread that calls encrypt and then a javascript function.
        try
        {
            Properties formHashtable = new Properties();
            if (form != null)
                formHashtable.load(new ByteArrayInputStream(form.getBytes(UTF8)));
            sendFileToUrlWithSecureMessagePrivate(
                    url,
                    prompt,
                    message,
                    fileParameterName,
                    filenameParameterName,
                    formHashtable,
                    sign,
                    signatureParameterName,
                    forceEncrypt,
                    onCompletionSuccess,
                    onCompletionFailure);
            }
            catch (Throwable t)
            {
                new JSException(t);
            }
	}		
	
	////
		public void sendFileToUrlWithQuestionAndAnswer(
			final String url,
			final String prompt,
			final String messageID,
			final String recipientAliases,
			final String question,
			final String answer,
			final String questionAndAnswerRecipientAliases,
			final String fileParameterName,
			final String filenameParameterName,
			String form,
			final boolean sign,
			final String signatureParameterName,
			final boolean forceEncrypt,
			final String onCompletionSuccess,
			final String onCompletionFailure)
		{
	        // Create thread that calls encrypt and then a javascript function.
	        try
	        {
	        	SecureMessage message = buildSecureMessage(
					recipientAliases, question, answer,
					questionAndAnswerRecipientAliases,
					null, messageID);
	            Properties formHashtable = new Properties();
	            if (form != null)
	                formHashtable.load(new ByteArrayInputStream(form.getBytes(UTF8)));
	            sendFileToUrlWithSecureMessagePrivate(
	                    url,
	                    prompt,
	                    message,
	                    fileParameterName,
	                    filenameParameterName,
	                    formHashtable,
	                    sign,
	                    signatureParameterName,
	                    forceEncrypt,
	                    onCompletionSuccess,
	                    onCompletionFailure);
            }
            catch (Throwable t)
            {
                new JSException(t);
            }
	}
	
	/**
	 * Asynchronously copy a file to a URL. Displays a file selection dialog.
	 * Supports encryption and signing.
	 * <p>
	 * <i>Keywords for the JavaScript callbacks (see class documentation)</i>
	 * <br>
	 * Success: PARAM_FILE
	 * <br>
	 * Failure: PARAM_FILE, PARAM_FAILURE_REASON
	 * 
	 * @param url the URL to which the file will be posted
	 * @param prompt the prompt to display in the file selection dialog
	 * @param aliases encrypt the file to these public keys (may be null)
	 * @param password encrypt the file with this password (may be null)
	 * @param fileParameterName the form variable in which the file will
	 *   be placed
	 * @param filenameParameterName the form variable in which the file name
	 *   will be placed
	 * @param form parameters to POST (ignored if method is not POST)
	 * @param sign sign the file with the current private key
	 * @param signatureParameterName the form variable in which the signature
	 *   will be placed
	 * @param forceEncrypt if neither aliases nor password are specified,
	 *   throw an exception (don't send plain text)
	 * @param onCompletionSuccess JavaScript to execute on success
	 * @param onCompletionFailure JavaScript to execute on failure
	 */
	public void sendFileToUrl(
		final String url,
		final String prompt,
		final Vector aliases,
		final String password,
		final String fileParameterName,
		final String filenameParameterName,
		Hashtable form,
		final boolean sign,
		final String signatureParameterName,
		final boolean forceEncrypt,
		final String onCompletionSuccess,
		final String onCompletionFailure)
	{
		try
		{
            SecureMessage message = new SecureMessage();
			String[] aliasArray = null;
			if (aliases != null)
			{
				aliasArray = new String[aliases.size()];
				for (int i = 0; i < aliases.size(); i++)
				{
					aliasArray[i] = (String) aliases.elementAt(i);
				}
			}
            message.setRecipientAliases(Conversions2.vectorToString(aliases, ","));
            Vector passwords = new Vector();
            passwords.addElement(password);
			message.setPasswords(passwords);
			sendFileToUrlWithSecureMessagePrivate(
				url,
				prompt,
				message,
				fileParameterName,
				filenameParameterName,
				form,
				sign,
				signatureParameterName,
				forceEncrypt,
				onCompletionSuccess,
				onCompletionFailure);
		}
		catch (Throwable t)
		{
			new JSException(t);
		}
	}

	/**
	 * Asynchronously copy a file to a URL. Displays a file selection dialog.
	 * Supports encryption and signing.
	 * <p>
	 * Identical to sendFileToUrl, except that it accepts the form parameter
	 * as a String in the format of a properties file.
	 * 
	 * @param url the URL to which the file will be posted
	 * @param prompt the prompt to display in the file selection dialog
	 * @param password encrypt the file with this password (may be null)
	 * @param aliases encrypt the file to these public keys (may be null)
	 * @param fileParameterName the form variable in which the file will
	 *   be placed
	 * @param filenameParameterName the form variable in which the file name
	 *   will be placed
	 * @param form parameters to POST (ignored if method is not POST)
	 * @param sign sign the file with the current private key
	 * @param signatureParameterName the form variable in which the signature
	 *   will be placed
	 * @param forceEncrypt if neither aliases nor password are specified,
	 *   throw an exception (don't send plain text)
	 * @param onCompletionSuccess JavaScript to execute on success
	 * @param onCompletionFailure JavaScript to execute on failure
	 */
	public void sendFileToUrl2(
		final String url,
		final String prompt,
		final String aliases,
		final String password,
		final String fileParameterName,
		final String filenameParameterName,
		final String form,
		final boolean sign,
		final String signatureParameterName,
		final boolean forceEncrypt,
		final String onCompletionSuccess,
		final String onCompletionFailure)
	{
		try
		{
            SecureMessage message = new SecureMessage();
            message.setRecipientAliases(aliases);
            if ( password != null )
            {
            	Vector passwords = new Vector();
            	passwords.addElement(password);
            	message.setPasswords(passwords);
            }
            sendFileToUrlWithSecureMessage(
				url,
				prompt,
                message,
				fileParameterName,
				filenameParameterName,
				form,
				sign,
				signatureParameterName,
				forceEncrypt,
				onCompletionSuccess,
				onCompletionFailure);
		}
		catch (Throwable t)
		{
			new JSException(t);
		}
	}

	/**
	 * When anonymous is true, no identifying information will be placed in outgoing
	 * encrypted messages, so they are suitable for BCC-ed messages.
	 * 
	 * @param anonymous true or false (defaults to false)
	 */
	public void setAnonymous(boolean anonymous)
	{
		try
		{
			myDelegate.setAnonymous(anonymous);
		}
		catch (Throwable e)
		{
			new JSException(e);
		}
	}

	public void setCharacterEncoding(String characterEncoding)
	{
		try
		{
			if ( characterEncoding != null )
				Conversions.checkCharacterEncoding(characterEncoding);
			this.characterEncoding = characterEncoding;
		}
		catch (Throwable e)
		{
			new JSException(e);
		}
	}

	/**
	 * Set the customerID associated with requests. This is initially set by the
	 * CustomerID parameter, but may be changed.  Creation date: (07/08/2001
	 * 18:23:24)
	 * 
	 * @param customerID java.lang.String
	 */
	public void setCustomerID(String customerID)
	{
		myDelegate.setCustomerID(customerID);
	}

	/**
	 * Sets the expiration time for the passphrase associated
	 * with an alias.
	 *
	 * @param alias the alias to set
	 * @param expirationTime the expiration time in seconds since 1970-01-01 00:00:00 UTC
	 * or -1 to set it to the default value for the domain.
	 */
	public void setPassphraseExpirationTime(String alias, long expirationTime)
	{
		try
		{
			myDelegate.setPassphraseExpirationTime(alias, expirationTime);
		}
		catch (Throwable e)
		{
			new JSException(e);
		}
	}
	
	public void setPgpCertificateAuthorityCertificate(String certificate)
			throws IOException, InvalidSignatureException,
			MissingSelfSignatureException
	{
		try
		{
			myDelegate.setPgpCertificateAuthorityCertificate(certificate);
		}
		catch (Throwable e)
		{
			new JSException(e);
		}
	}

	/**
	 * Turns on or off graphical progress indicators that display during
	 * streaming operations.
	 * 
	 * @param useProgressIndicators
	 */
	public void setUseProgressIndicators(boolean useProgressIndicators)
	{
		myDelegate.useProgressIndicators(useProgressIndicators);
	}

	/**
	 * Asynchronously signs a file directly on disk.  Displays a file
	 * selection dialog.  Authentication must be performed first.
	 * <p>
	 * <i>Keywords for the JavaScript callbacks (see class documentation)</i>
	 * <br>
	 * Success: PARAM_FILE, PARAM_SIGNATURE
	 * <br>
	 * Failure: PARAM_FILE, PARAM_FAILURE_REASON
	 * 
	 * @param prompt the prompt to display in the file selection dialog
	 * @param onCompletionSuccess JavaScript to execute on success
	 * @param onCompletionFailure JavaScript to execute on failure
	 */
	public void signFile(
		final String prompt,
		final String onCompletionSuccess,
		final String onCompletionFailure)
	{
		try
		{
			Thread signingThread = new Thread(new Runnable()
			{
				public void run()
				{
					String filepath = null;
					String signatureString = null;
					try
					{
						filepath = myDelegate.selectFile(null, prompt, LOAD);
						if (filepath == null)
							return;
						signatureString =
							Conversions.byteArrayToString(
								myDelegate.signFile(filepath),
								UTF8);
					}
					catch (Throwable t)
					{
						new JSException(t);

						// Something went wrong, call the 'onCompleteFailure'
						callJavascript(
							onCompletionFailure,
							new String[] { PARAM_FILE, PARAM_FAILURE_REASON },
							new String[] { filepath, t.getMessage()});
						return;
					}
					try
					{
						// Handle success.
						callJavascript(
							onCompletionSuccess,
							new String[] { PARAM_FILE, PARAM_SIGNATURE, },
							new String[] { filepath, signatureString });
					}
					catch (Throwable t)
					{
						new JSException(t);
						return;
					}
				}
			});
			signingThread.start();
		}
		catch (Throwable t)
		{
			new JSException(t);
		}
	}

	/**
	 * Signs a piece of text using the current private key.
	 * 
	 * @param text the text to be signed
	 * @param detach boolean indicating whether or not a detached signature
	 *        should be returned.
	 * @return the signed text.
	 */
	public String signText(String text, boolean detach)
	{
		try
		{
			return myDelegate.signText(text, characterEncoding, detach);
		}
		catch (Throwable e)
		{
			new JSException(e);
			return null;
		}
	}

	/**
	 * Called when the web browser moves to another page or is closed.
	 */
	public void stop()
	{
		try
		{
			if (onStopUrl != null && ! "".equals(onStopUrl.trim()))
			{
				HttpRequest httpRequest = new HttpRequest(onStopUrl);
				httpRequest.open();
				httpRequest.connect();
			}
		}
		catch (IOException e)
		{
			e.printStackTrace();
		}
	}

	/**
	 * Strip method definition from a JavaScript function.
	 * 
	 * @param jsFunction the function
	 * @return the function body, without the definition 
	 */
	private String stripMethodDefinition(String jsFunction)
	{
		int firstSeagus = jsFunction.indexOf('{');
		int lastSeagus = jsFunction.lastIndexOf('}');

		if ((firstSeagus < 0) | (lastSeagus < 0))
		{
			throw new IllegalArgumentException("Illegal javascript definition");
		}

		return jsFunction.substring(firstSeagus + 1, lastSeagus);
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
		String cert,
		String alias,
		String activationCode)
	{
		try
		{
			return myDelegate.uploadCertificate(cert, alias, activationCode);
		}
		catch (Throwable e)
		{
			new JSException(e);
			return null;
		}
	}

	/**
	 * Indicate whether or not the file encryption operations should use ASCII
	 * armoring.  ASCII armoring will base-64 encode the encrypted data and add
	 * headers and footers indicating the message type.  It will increase the
	 * size of the file, and reduce the speed of the encryption and decryption
	 * processes. ASCII armoring is off by default.
	 * 
	 * @param useArmor true to turn armoring on, false to turn it off
	 */
	public void useArmor(boolean useArmor)
	{
		myDelegate.useArmor(useArmor);
	}

	/**
	 * Indicates whether ASCII armoring for encryption to files is on or off.
	 * 
	 * @return true if armoring is on, false if it is off
	 */
	public boolean usesArmor()
	{
		return myDelegate.usesArmor();
	}

	/**
	 * Verifies a signature on text using the public key for the given alias.
	 * 
	 * @param text the text that has been signed.
	 * @param signature the detached signature.
	 * @param signer the alias of the signer.
	 * @return SIGNATURE_VALID, SIGNATURE_INVALID, NO_CERTIFICATE_FOUND, or ERROR
	 */
	public int verifyDetached(String text, String signature, String signer)
	{
		try
		{
			return myDelegate.verifyText(signer, text, signature, null, null);
		}
		catch (Throwable e)
		{
			new JSException(e);
			return ERROR;
		}
	}

	/**
	 * Verifies a signature on text using the public key for the given alias.
	 * 
	 * @param text the text that has been signed [in]
	 * @param signature the detached signature [in]
	 * @param allVerifiedSigners the aliases verified to have signed the text
	 *        [out]
	 * @return SIGNATURE_VALID, SIGNATURE_INVALID, NO_CERTIFICATE_FOUND, or ERROR
	 */
	public int verifyDetached2(
		String text,
		String signature,
		Vector allVerifiedSigners,
		Vector allForgedSigners)
	{
		try
		{
			signatureSuccesses = null;
			signatureFailures = null;
			int retVal =
				myDelegate.verifyText(
					null,
					text,
					signature,
					allVerifiedSigners,
					allForgedSigners);
			signatureSuccesses = allVerifiedSigners;
			signatureFailures = allForgedSigners;
			return retVal;
		}
		catch (Throwable e)
		{
			new JSException(e);
			return ERROR;
		}
	}

	/**
	 * Verifies a signature on text using the public key for the given alias.
	 * 
	 * @param text the text that has been signed
	 * @param signature the detached signature
	 * @return SIGNATURE_VALID, SIGNATURE_INVALID, NO_CERTIFICATE_FOUND, or ERROR
	 */
	public int verifyDetached3(String text, String signature)
	{
		signatureSuccesses = null;
		signatureFailures = null;
		return verifyDetached2(text, signature, new Vector(), new Vector());
	}

	/**
	 * Asynchronously verify a signature on a file. Displays a file selection dialog.
	 * <p>
	 * <i>Keywords for the JavaScript callbacks (see class documentation)</i>
	 * <br>
	 * Success: PARAM_FILE, PARAM_VERIFIED_SIGNERS, PARAM_FAILED_SIGNERS,
	 *   PARAM_SIGNATURE_VERIFICATION_CODE
	 * <br>
	 * Failure: PARAM_FILE, PARAM_FAILURE_REASON
	 * 
	 * @param prompt the prompt to display in the file selection dialog
	 * @param signature verify the file against this signature
	 * @param signerDelimiter when returning the lists of signers, separate
	 *   each entry with this string
	 * @param onCompletionSuccess JavaScript to execute on success
	 * @param onCompletionFailure JavaScript to execute on failure
	 */
	public void verifyFile(
		final String prompt,
		final String signature,
		final String signerDelimiter,
		final String onCompletionSuccess,
		final String onCompletionFailure)
	{
		// Create thread that calls password encrypt and then a javascript function.
		try
		{
			Thread verificationThread = new Thread(new Runnable()
			{
				public void run()
				{
					int signatureVerificationCode = -1;
					Vector allVerifiedSigners = new Vector();
					Vector allFailedSigners = new Vector();
					String filepath = null;
					try
					{
						filepath = myDelegate.selectFile(null, prompt, LOAD);
						if (filepath == null)
							return;
						signatureVerificationCode =
							myDelegate.verifyFile(
								null,
								filepath,
								signature,
								allVerifiedSigners,
								allFailedSigners);
					}
					catch (Throwable t)
					{
						new JSException(t);

						// Something went wrong, call the 'onCompleteFailure'
						callJavascript(
							onCompletionFailure,
							new String[] { PARAM_FILE, PARAM_FAILURE_REASON },
							new String[] { filepath, t.getMessage()});
						return;
					}
					try
					{
						// Handle success.
						callJavascript(
							onCompletionSuccess,
							new String[] {
								PARAM_FILE,
								PARAM_VERIFIED_SIGNERS,
								PARAM_FAILED_SIGNERS,
								PARAM_SIGNATURE_VERIFICATION_CODE },
							new String[] {
								filepath,
								Conversions2.vectorToString(
									allVerifiedSigners,
									signerDelimiter),
								Conversions2.vectorToString(
									allFailedSigners,
									signerDelimiter),
								String.valueOf(signatureVerificationCode)});
					}
					catch (Throwable t)
					{
						new JSException(t);
						return;
					}
				}
			});
			verificationThread.start();
		}
		catch (Throwable t)
		{
			new JSException(t);
		}
	}

	/**
	 * Verifies a signature on text using the public key for the given alias.
	 * 
	 * @param textWithSig the text that has been signed, including the signature.
	 * @param signer the alias of the signer.
	 * @return SIGNATURE_VALID, SIGNATURE_INVALID, NO_CERTIFICATE_FOUND,
	 *         NO_SIGNATURE_FOUND, or ERROR
	 */
	public int verifyText(String textWithSig, String signer)
	{
		try
		{
			signatureSuccesses = null;
			signatureFailures = null;
			signer = signer.toLowerCase();
			return myDelegate.verifyCleartextSignedMessage(
				signer,
				textWithSig,
				null,
				null,
				null,
				characterEncoding);

		}
		catch (Throwable e)
		{
			new JSException(e);
			return ERROR;
		}
	}

	/**
	 * Verifies a signature on text using the public key for the given alias.
	 * 
	 * @param textWithSig the text that has been signed, including the signature
	 *        [in].
	 * @param allVerifiedSigners the aliases verified to be signed the message
	 *        [out].
	 * @return SIGNATURE_VALID, SIGNATURE_INVALID, NO_CERTIFICATE_FOUND,
	 *         NO_SIGNATURE_FOUND, or ERROR
	 */
	public int verifyText2(
		String textWithSig,
		Vector allVerifiedSigners,
		Vector allForgedSigners,
		Vector textWithoutSignature)
	{
		try
		{
			signatureSuccesses = null;
			signatureFailures = null;
			String[] textWithoutSignatureArray = new String[1];
			int retVal =
				myDelegate.verifyCleartextSignedMessage(
					null,
					textWithSig,
					allVerifiedSigners,
					allForgedSigners,
					textWithoutSignatureArray,
					characterEncoding);

			textWithoutSignature.removeAllElements();

			if (textWithoutSignatureArray[0] != null)
			{
				textWithoutSignature.addElement(textWithoutSignatureArray[0]);
			}
			signatureSuccesses = allVerifiedSigners;
			signatureFailures = allForgedSigners;
			return retVal;
		}
		catch (Throwable e)
		{
			new JSException(e);
			return ERROR;
		}
	}

	/**
	 * Verifies a signature on text using the public key for the given alias.
	 * 
	 * @param textWithSig the text that has been signed, including the signature
	 * @return SIGNATURE_VALID, SIGNATURE_INVALID, NO_CERTIFICATE_FOUND,
	 *         NO_SIGNATURE_FOUND, or ERROR
	 */
	public int verifyText3(String textWithSig)
	{
		signatureSuccesses = null;
		signatureFailures = null;
		return verifyText2(
			textWithSig,
			new Vector(),
			new Vector(),
			new Vector());
	}

	/**
	 * Sets the maximum size for post requests.  (sendFileToUrl).
	 */
	public void setMaximumPostRequestContentLength(long maximumPostRequestContentLength)
	{
		this.maximumPostRequestContentLength = maximumPostRequestContentLength;
	}

	public void setNewEncryptionKeyAlgorithm(String newEncryptionKeyAlgorithm)
	{
		myDelegate.setNewEncryptionKeyAlgorithm(newEncryptionKeyAlgorithm);
	}

	public void setNewEncryptionKeySize(int newEncryptionKeySize)
	{
		myDelegate.setNewEncryptionKeySize(newEncryptionKeySize);
	}

	public void setNewKeySignatureHashAlgorithm(String newKeySignatureHashAlgorithm)
	{
		myDelegate.setNewKeySignatureHashAlgorithm(newKeySignatureHashAlgorithm);
	}

	public void setNewKeySymmetricAlgorithm(String newKeySymmetricAlgorithm)
	{
		myDelegate.setNewKeySymmetricAlgorithm(newKeySymmetricAlgorithm);
	}

	public void setNewSigningKeyAlgorithm(String newSigningKeyAlgorithm)
	{
		myDelegate.setNewSigningKeyAlgorithm(newSigningKeyAlgorithm);
	}

	public void setNewSigningKeySize(int newSigningKeySize)
	{
		myDelegate.setNewSigningKeySize(newSigningKeySize);
	}
	
	private SecureMessage buildSecureMessage(String recipientAliases,
			String question, String answer,
			String questionAndAnswerRecipientAliases, String body,
			String messageID)
	{
		SecureMessage secureMessage = createSecureMessage();
		if ( recipientAliases != null )
		{
			secureMessage.setRecipientAliases(recipientAliases);
		}
		if (question != null && !"".equals(question) && answer != null
				&& !"".equals(answer)
				&& questionAndAnswerRecipientAliases != null
				&& !"".equals(questionAndAnswerRecipientAliases))
		{
			QuestionAndAnswer qa = new QuestionAndAnswer();
			qa.setQuestion(question);
			qa.setAnswer(answer);
			qa.setRecipientAliases(questionAndAnswerRecipientAliases);
			if (messageID != null && answerSalts.get(messageID) != null)
				qa.setAnswerSalt((String) answerSalts.get(messageID));
			Vector qav = new Vector();
			qav.addElement(qa);
			secureMessage.setQuestionsAndAnswers(qav);
			qav.addElement(qav);
		}
		secureMessage.setUseArmor(true);
		if ( body != null )
			secureMessage.setInputText(body);
		if ( messageID != null && secureMessage.getFirstAnswerSalt() != null )
			answerSalts.put(messageID, secureMessage.getFirstAnswerSalt());
		return secureMessage;
	}
}