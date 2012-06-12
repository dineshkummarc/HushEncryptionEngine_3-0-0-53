/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.hee.legacy;

import java.awt.Button;
import java.awt.Color;
import java.awt.Frame;
import java.awt.GridLayout;
import java.awt.Label;
import java.awt.TextField;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Hashtable;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.engines.ElGamalEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import com.hush.pgp.DataFormatException;
import com.hush.pgp.PgpConstants;
import com.hush.pgp.io.IntegrityCheckFailureException;
import com.hush.util.ArrayTools;
import com.hush.util.Base64;
import com.hush.util.Conversions;

public class LegacyHushmail implements PgpConstants, ActionListener
{

	/**
	 * Indicates the beginning of HushMail 1.0 formatted content.
	 */
	private static final String BEGIN_HUSHMAIL_1_0_TAG =
		"----- HushMail v1.0 -----";

	/**
	 * Indicates the beginning of HushMail 1.11 formatted content.
	 */
	private static final String BEGIN_HUSHMAIL_1_11_TAG =
		"----- HushMail v1.11 -----";

	/**
	 * Indicates the beginning of HushMail 1.3 formatted content.
	 */
	private static final String BEGIN_HUSHMAIL_1_3_TAG =
		"----- HushMail v1.3 -----";

	/**
	 * The algorithm to be used for hashes.
	 */
	private static final String HASH_ALGORITHM = "SHA1";

	/**
	 * The token that separates the hash at the end of the content
	 * from the rest of the content.
	 */
	private static final String HASH_SEPARATOR = "-";

	/**
	 * Delimiter marking the end of an encrypted message.
	 */
	private static final String HUSH_END_HEADER = "----- End -----";

	/**
	 * The HushMail version delimiter, marking the beginning of the encoded ciphertext.
	 * Subclasses need to initialize this value in their constructor.
	 */
	private static String hushmailBeginHeader = "";

	/**
	 * A paramater referencing an array of keyblocks.
	 */
	public static final String KEYBLOCKS_PARAMETER = "keyblocks";

	/**
	 * This is used for Hushmail 1.0/1.11
	 * should be Boolean with value true if message is 1.0 or 1.11 Private and false if 1.0 or 1.11 Public.
	 */
	public static final String PRIVATE_FORMAT = "privateFormat";

	/**
	 * A parameter referencing the session key.
	 */
	private static final String SESSION_KEY_PARAMETER = "sessionKey";

	private boolean base64 = true;

	/**
	 * After a message is parsed or encrypted, the raw bytes of the
	 * ciphertext are stored here.
	 */
	private byte[] cipherText;

	private byte[] encryptedBodyHash;

	private Frame frame;

	private Hashtable parameters;

	/**
	 * The unencrypted content is stored here.
	 */
	private byte[] plainText;

	private boolean useBrokenBlowfish = false;
	
	private boolean stripInitialBytes = true;

	public void actionPerformed(ActionEvent e)
	{
		if (e.getActionCommand().equalsIgnoreCase("ok"))
		{
			frame.setVisible(false);
			frame.dispose();
		}
	}

	/**
	 * Should be overridden to decode data using the encoding appropriate for the HushMail version.
	 * Creation date: (24/11/2000 16:35:08)
	 *
	 * @param data the data to be decoded.
	 *
	 * @return the decoded data.
	 */
	private byte[] decode(String data)
	{
		if (base64)
			return Base64.decode(data);
		return Conversions.hexStringToBytes(removeNewlines(data));
	}

	/**
	  * Decrypts content using decryptionKey. 
	  * For some content formats, e.g. PGP, the content          
	  * has several recipients and hence several public key encrypted session keys. In that 
	  * case it is necessary to specify a recipient certificate.    
	  *
	  * @param recipient the certificate of the private key owner.
	  *
	  * @param key the key that will decrypt the content.
	 *
	  * @exception CertificateException if there is a problem with the certificate.
	  *
	  * @exception InvalidKeyException if the private key is not appropriate for the operation.
	  *
	  * @exception NoSuchAlgorithmException if the algorithm implementation required to decrypt the content cannot be found.
	 *
	  * @exception BadDataFormatException if decryption fails because the data is not in a valid format.
	  */
	public void decrypt(CipherParameters decryptionKey)
		throws InvalidCipherTextException, IntegrityCheckFailureException
	{

		// Make sure that the keyblock parameter has been set.
		// Otherwise, we can't find the session key to decrypt the content.
		if (parameters.get(KEYBLOCKS_PARAMETER) == null)
		{
			throw new IllegalStateException(
				"Must set the "
					+ KEYBLOCKS_PARAMETER
					+ " parameter before decrypting! "
					+ "The keyblock can be found in the 'Hush-keyblock' header of a HushMail email message "
					+ "and should be placec in position 0 of the array.");
		}

		// Get the keyblock.  We assume there will be only one, 
		// and it will be the first in the array
		String keyblock = (String) parameters.get(KEYBLOCKS_PARAMETER);

		byte[] toProcess = decode(keyblock);

		byte[] sessionKeyBytes = new byte[16];

		byte[] storedsha = new byte[20];

		byte[] totalDecryptedBlock;

		if ("true".equals((String) parameters.get(PRIVATE_FORMAT)))
		{
			frame = new Frame("Please enter your passphrase");

			Label label =
				new Label("Your passphrase must be entered to decrypt this message");
			TextField textField = new TextField();
			Button button = new Button("Ok");

			textField.setEchoChar('*');

			frame.setBackground(new Color(0xD7, 0xE4, 0xF0));
			frame.setLayout(new GridLayout(3, 1));
			frame.add(label);
			frame.add(textField);
			frame.add(button);

			frame.pack();
			frame.setVisible(true);
			frame.setResizable(false);

			button.setActionCommand("ok");
			button.addActionListener(this);

			while (frame.isVisible())
			{
				try
				{
					Thread.sleep(200);
				}
				catch (Exception e)
				{
				}
			}

			decryptionKey =
				new KeyParameter(
					Conversions.stringToByteArray(
						textField.getText(),
						UTF8));

			PaddedBufferedBlockCipher keyBlockCipher =
				new PaddedBufferedBlockCipher(new CBCBlockCipher(getCipher()));

			byte[] iv = new byte[8];

			System.arraycopy(toProcess, 0, iv, 0, 8);

			// For whatever reason, the IV is encrypted
			BlockCipher decryptIV = getCipher();

			decryptIV.init(false, decryptionKey);
			decryptIV.processBlock(iv, 0, iv, 0);

			keyBlockCipher.init(false, new ParametersWithIV(decryptionKey, iv));

			totalDecryptedBlock =
				new byte[keyBlockCipher.getOutputSize(toProcess.length - 8)];

			int processed =
				keyBlockCipher.processBytes(
					toProcess,
					8,
					toProcess.length - 8,
					totalDecryptedBlock,
					0);

			keyBlockCipher.doFinal(totalDecryptedBlock, processed);
		}
		else
		{

			// Decrypt the keyblock to retrieve the session key.
			//Cipher keyBlockCipher = Cipher.getInstance(ASYMMETRIC_ALGORITHM);
			ElGamalEngine keyBlockCipher = new ElGamalEngine();

			keyBlockCipher.init(false, decryptionKey);

			totalDecryptedBlock =
				keyBlockCipher.processBlock(toProcess, 0, toProcess.length);
		}

		System.arraycopy(totalDecryptedBlock, 0, sessionKeyBytes, 0, 16);
		System.arraycopy(totalDecryptedBlock, 16, storedsha, 0, 20);

		SHA1Digest sha = new SHA1Digest();

		sha.update(sessionKeyBytes, 0, 16);

		byte[] sharesult = new byte[20];

		sha.doFinal(sharesult, 0);

		if (!ArrayTools.equals(sharesult, 0, storedsha, 0, 20))
			throw new IntegrityCheckFailureException("SHA1 hash on key block failed");

		byte[] iv = new byte[8];

		System.arraycopy(cipherText, 0, iv, 0, 8);

		// Then decrypt the message body;
		PaddedBufferedBlockCipher msgCipher =
			new PaddedBufferedBlockCipher(new CBCBlockCipher(getCipher()));

		msgCipher.init(
			false,
			new ParametersWithIV(new KeyParameter(sessionKeyBytes), iv));

		byte[] plainTextWithRandomBytesAtStart =
			new byte[msgCipher.getOutputSize(cipherText.length - 8)];

		int processed =
			msgCipher.processBytes(
				cipherText,
				8,
				cipherText.length - 8,
				plainTextWithRandomBytesAtStart,
				0);

		msgCipher.doFinal(plainTextWithRandomBytesAtStart, processed);

		// Decrypt and check the hash that was parsed out in the generateContentHolder method.
		//byte[] storedHash = msgCipher.doFinal(encryptedBodyHash);
		//MessageDigest hashCheck = MessageDigest.getInstance(HASH_ALGORITHM);
		//hashCheck.update(plainTextWithRandomBytesAtStart);
		/*
		byte[] actualHash = hashCheck.digest();
		
		for (int n = 0; n < actualHash.length; n++)
		{
			if (actualHash[n] != storedHash[n])
			{
				throw new BadDataFormatException(
					"Verification of message by hash failed. "
						+ "Content has been corrupted or tampered with.");
			}
		}
		*/

		if ( ! stripInitialBytes )
		{
			plainText = plainTextWithRandomBytesAtStart;
			return;
		}
			
		// Messages all have 8 bytes of random data at beginning.
		// This protects against attacks against short messages.
		// The reasoning was, it might be possible to crack a one word message
		// by encrypting every word in the dictionary with the recipients public key.
		// However, the randomly generated session key used to encrypt the
		// body should protect against this, anyway.  I'm not sure this is necessary.
		plainText = new byte[plainTextWithRandomBytesAtStart.length - 8];
		System.arraycopy(
			plainTextWithRandomBytesAtStart,
			8,
			plainText,
			0,
			plainText.length);

	}

	public byte[] getPlainText()
	{
		return plainText;
	}

	private String removeNewlines(String in)
	{
		StringBuffer buf = new StringBuffer();
		for (int x = 0; x < in.length(); x++)
		{
			if (in.charAt(x) != '\r' && in.charAt(x) != '\n')
				buf.append(in.charAt(x));
		}
		return buf.toString();
	}

	public void setFormatted(String formattedString) throws DataFormatException
	{
		formattedString = formattedString.trim();

		String headerString;

		if (formattedString.indexOf(BEGIN_HUSHMAIL_1_3_TAG) == 0)
		{
			headerString = BEGIN_HUSHMAIL_1_3_TAG;
		}
		else if (formattedString.indexOf(BEGIN_HUSHMAIL_1_11_TAG) == 0)
		{
			headerString = BEGIN_HUSHMAIL_1_11_TAG;
			base64 = false;
		}
		else if (formattedString.indexOf(BEGIN_HUSHMAIL_1_0_TAG) == 0)
		{
			headerString = BEGIN_HUSHMAIL_1_0_TAG;
			base64 = false;
			useBrokenBlowfish = true;
			stripInitialBytes = false;
		}
		else
			throw new DataFormatException("Unrecognized header");

		// Be sure that the proper header ends the message
		int endHeaderLocation = formattedString.indexOf(HUSH_END_HEADER);

		if (endHeaderLocation == -1)
		{
			throw new DataFormatException(
				"Header missing: " + HUSH_END_HEADER);
		}

		// Remove the header and footer
		formattedString =
			formattedString.substring(headerString.length(), endHeaderLocation);

		// Store the hash
		encryptedBodyHash =
			Base64.decode(
				formattedString.substring(
					formattedString.indexOf(HASH_SEPARATOR) + 1));

		// Remove the hash
		formattedString =
			formattedString.substring(
				0,
				formattedString.indexOf(HASH_SEPARATOR));

		cipherText = decode(formattedString);

	}

	public void setParameters(Hashtable parameters)
	{
		this.parameters = parameters;
	}

	private BlockCipher getCipher()
	{
		LegacyBlowfishEngine cipher = new LegacyBlowfishEngine();
		if (useBrokenBlowfish)
			cipher.simulateKeyExpansionBug();
		return cipher;
	}
}