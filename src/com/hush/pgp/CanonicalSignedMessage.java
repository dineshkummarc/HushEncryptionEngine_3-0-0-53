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
import java.io.IOException;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.security.SecureRandom;
import java.util.Hashtable;
import java.util.Vector;

import com.hush.util.ArrayTools;
import com.hush.util.Conversions;
import com.hush.util.ExceptionWrapper;
import com.hush.util.Logger;
import com.hush.util.UnrecoverableKeyException;

/**
 * This class creates or verifies a cleartext signed message.
 * 
 * 
 * Character encoding precedence rules:
 * 
 * HIGHEST
 * <ol>
 * <li>Specified with setCharacterEncoding.</li>
 * <li>Specified in PGP SIGNED MESSAGE header.</li>
 * <li>Specified in PGP SIGNATURE header.</li>
 * </ol>
 * LOWEST
 */
public class CanonicalSignedMessage implements PgpConstants
{

	private static final String DASH_ESCAPE = "- ";

	private String characterEncoding = null;

	private Hashtable headers = new Hashtable();

	private Vector signatures = new Vector();

	private String text;

	private int mostRecentHashAlgorithm = -1;
	
	private int hashAlgorithm = -1;
	
	private boolean overrideHeaderCharacterEncoding = false;

	private final String sigHeader =
		Conversions.byteArrayToString(ARMOR_HEADER_PGP_SIGNATURE, UTF8);
	private final int sigHeaderLength = sigHeader.length();
	
	/**
	 * 
	 */
	public CanonicalSignedMessage()
	{
		headers.put(ARMOR_HEADER_KEY_VERSION, VERSION);
	}

	/**
	 * Returns the character encoding, which is UTF-8 by default.
	 */
	public String getCharacterEncoding()
	{
		if (characterEncoding == null
			|| characterEncoding.equals(UTF8_ALTERNATE))
			return UTF8;
		return characterEncoding;
	}

	/**
	 * Returns a header.
	 */
	public String getHeader(String key) throws IOException
	{
		return (String) headers.get(key);
	}

	public Signature[] getSignatures()
	{
		Signature[] retVal = new Signature[signatures.size()];
		signatures.copyInto(retVal);
		return retVal;
	}

	public byte[][] getSigners()
	{
		Vector signers = new Vector();
		for (int x = 0; x < signatures.size(); x++)
			signers.addElement(
				((Signature) signatures.elementAt(x)).getIssuerKeyID(false));
		byte[][] retVal = new byte[signers.size()][];
		signers.copyInto(retVal);
		return retVal;
	}

	/**
	 * Returns the text portion of the cleatext signed message.
	 * 
	 * @return the text
	 */
	public String getText()
	{
		return text;
	}

	public void setSignedMessage(String signedMessage)
		throws DataFormatException, IOException
	{
		BufferedReader myReader =
			new BufferedReader(new StringReader(signedMessage));
		String line = myReader.readLine();
		while ("".equals(line))
			line = myReader.readLine();
		if (!Conversions
				.byteArrayToString(ARMOR_HEADER_PGP_SIGNED_MESSAGE, UTF8)
				.equals(line.trim()))
			throw new DataFormatException("First line is not a PGP signed message header");
		line = myReader.readLine();
		boolean localOverrideCharacterEncoding = overrideHeaderCharacterEncoding
			&& characterEncoding != null;
		String localCharacterEncoding = characterEncoding;
		while (line != null && !"".equals(line.trim()))
		{
			int colonIndex = line.indexOf(":");
			if ( colonIndex != -1 && line.length() > colonIndex + 3 )
			{
				String key = line.substring(0, colonIndex).trim();
				String value = line.substring(colonIndex + 1).trim();
				headers.put(key, value);
				// If a character encoding has not been locked in, and one is
				// found in the headers, use the one in the headers.
				if (!localOverrideCharacterEncoding
						&& ARMOR_HEADER_KEY_CHARSET.equalsIgnoreCase(key))
				{
					try
					{
						Conversions.checkCharacterEncoding(value);
						localCharacterEncoding = value;
					}
					catch (UnsupportedEncodingException e)
					{
						Logger.log(
							this,
							Logger.ERROR,
							"Unsupported encoding " + value);
					}
				}
			}
			line = myReader.readLine();
		}

		StringBuffer textBuffer = new StringBuffer();
		line = myReader.readLine();
		while (line != null
				&& (line.length() < sigHeaderLength
						|| line.indexOf(sigHeader) != 0 || line.trim().length() != sigHeaderLength))
		{
			
			if (line.length() > 2 && line.substring(0, 2).equals(DASH_ESCAPE))
				textBuffer.append(line.substring(2));

			else
				textBuffer.append(line);
			textBuffer.append("\r\n");
			line = myReader.readLine();
		}

		if (line == null)
			throw new IOException("String ends before the signature begins");

		text = textBuffer.toString();

		textBuffer = null;

		StringBuffer signatureBuffer = new StringBuffer();

		signatureBuffer.append(line);
		signatureBuffer.append("\r\n");

		while ((line = myReader.readLine()) != null)
		{
			signatureBuffer.append(line);
			signatureBuffer.append("\r\n");
		}
		Signature[] signatureArray =
			Signature.load(
				new ByteArrayInputStream(
					Conversions.stringToByteArray(
						signatureBuffer.toString(),
						getCharacterEncoding())), localCharacterEncoding,
						localOverrideCharacterEncoding);

		for (int x = 0; x < signatureArray.length; x++)
		{
			signatures.addElement(signatureArray[x]);
		}
	}

	/**
	 * Set the character encoding.  By default, message headers will override
	 * this if found.
	 */
	public void setCharacterEncoding(String characterEncoding)
		throws UnsupportedEncodingException
	{
		if (characterEncoding != null)
			Conversions.checkCharacterEncoding(characterEncoding);
		this.characterEncoding = characterEncoding;
	}

	/**
	 * Sets the text over which the signature will be generated,
	 * canonicalizing it.
	 * 
	 * @param text the text
	 */
	public void setText(String text)
	{
		try
		{
			StringBuffer canonicalTextBuffer = new StringBuffer();
			BufferedReader myReader =
				new BufferedReader(new StringReader(text));
			String line;
			while ((line = myReader.readLine()) != null)
			{
				line = ("x" + line).trim().substring(1);
				canonicalTextBuffer.append(line);
				canonicalTextBuffer.append("\r\n");
			}
			this.text = canonicalTextBuffer.toString();
		}
		catch (IOException e)
		{
			throw ExceptionWrapper.wrapInRuntimeException("IOException that should never happen",
					e);
		}
	}

	/**
	 * Iterates through each signature the message, and if it matches the
	 * key ID on the given key, an attempt is made to verify the signature.
	 * All the signatures that are verified are returned.
	 * <p>
	 * If a signature failes verification, an exception will only be thrown
	 * if <code>dieOnFailure</code> is set to true.
	 * 
	 * @param key the key with which to attempt verification
	 * @param dieOnFailure if true, throw an exception if a signature verification
	 *   fails
	 * @throws com.hush.pgp.InvalidSignatureException if die=OnFailure is true,
	 *   and a signature fails to verify
	 * @return an array of verified signatures
	 */
	public Signature[] verifySignatures(Key key, boolean dieOnFailure)
		throws InvalidSignatureException
	{
		Vector verified = new Vector();
		Signature sig;
		for (int x = 0; x < signatures.size(); x++)
		{
			sig = (Signature) signatures.elementAt(x);
			if (ArrayTools
				.equals(
					sig.getIssuerKeyID(false),
					PgpConstants.WILD_CARD_KEY_ID)
				|| ArrayTools.equals(sig.getIssuerKeyID(false), key.getKeyID()))
			{
				sig.startVerification();
				sig.update(text);
				try
				{
					sig.finishVerification(key);
					verified.addElement(sig);
				}
				catch (InvalidSignatureException e)
				{
					if (dieOnFailure)
						throw e;
				}
			}
		}
		Signature[] retVal = new Signature[verified.size()];
		signatures.copyInto(retVal);
		return retVal;

	}

	/**
	 * Signs the text, and returns a cleartext signed message.
	 * 
	 * @param signer
	 * @throws PgpException
	 */
	public void signMessage(Key signer, SecureRandom random, long time)
		throws UnrecoverableKeyException
	{
		Signature sig = new Signature();
		try
		{
			sig.setCharacterEncoding(getCharacterEncoding());
		}
		catch (UnsupportedEncodingException e)
		{
			throw ExceptionWrapper
					.wrapInRuntimeException(
							"Should never happen as character encoding was already checked",
							e);
		}
		if ( hashAlgorithm != -1 )
			sig.setHashAlgorithm(hashAlgorithm);
		sig.startSigning(signer, Signature.SIGNATURE_ON_CANONICAL_TEXT, time);
		sig.update(text);
		sig.finishSigning(random);
		signatures.addElement(sig);
		if (mostRecentHashAlgorithm != -1 && mostRecentHashAlgorithm != sig.getHashAlgorithm())
		{
			throw new IllegalArgumentException("You can't put signatures with different hash algorithms on the same message");
		}
		mostRecentHashAlgorithm = sig.getHashAlgorithm();
	}

	public void setHeader(String key, String value)
	{
		headers.put(key, value);
	}

	public void setHeaders(Hashtable headers)
	{
		this.headers = headers;
	}

	public String getSignedMessage()
	{
		try
		{
			StringBuffer signedMessage = new StringBuffer(text.length() + 1024);
			signedMessage.append(
					Conversions.byteArrayToString(
						ARMOR_HEADER_PGP_SIGNED_MESSAGE,
						UTF8));
			signedMessage.append("\r\n");
			/* BREAKS SOME PGP CLIENTS
			Enumeration headerKeys = headers.keys();
			while (headerKeys.hasMoreElements())
			{
				String key = (String) headerKeys.nextElement();
				signedMessage.append(key);
				signedMessage.append(": ");
				signedMessage.append((String) headers.get(key));
				signedMessage.append("\r\n");
			}
			*/
			signedMessage.append(ARMOR_HEADER_KEY_HASH);
			signedMessage.append(": ");
			signedMessage.append(HASH_STRINGS[mostRecentHashAlgorithm]);
			signedMessage.append("\r\n");
			//signedMessage.append(ARMOR_HEADER_KEY_CHARSET);
			//signedMessage.append(": ");
			//signedMessage.append(getCharacterEncoding());
			//signedMessage.append("\r\n");

			signedMessage.append("\r\n");

			BufferedReader myReader =
				new BufferedReader(new StringReader(text));
			String line;
			while ((line = myReader.readLine()) != null)
			{
				if (line.length() > 0 && line.substring(0, 1).equals("-"))
				{
					signedMessage.append(DASH_ESCAPE);
				}
				signedMessage.append(line);
				signedMessage.append("\r\n");

			}
			Signature[] mySignatures = new Signature[signatures.size()];
			signatures.copyInto(mySignatures);
			signedMessage.append(Signature.toString(mySignatures, headers));
			return signedMessage.toString();
		}
		catch (IOException e)
		{
			throw ExceptionWrapper.wrapInRuntimeException("IOException that should never happen",
					e);
		}
	}

	public String getArmoredSignatures()
	{
		Signature[] mySignatures = new Signature[signatures.size()];
		signatures.copyInto(mySignatures);
		return Signature.toString(mySignatures, headers);
	}

	public void setHashAlgorithm(int hashAlgorithm)
	{
		this.hashAlgorithm = hashAlgorithm;
	}

	/**
	 * If this is set, any character encoding found in the headers will
	 * be overridden by the encoding set by setCharacterEncoding()
	 */
	public boolean getOverrideHeaderCharacterEncoding()
	{
		return overrideHeaderCharacterEncoding;
	}
	
	/**
	 * If this is set, any character encoding found in the headers will
	 * be overridden by the encoding set by setCharacterEncoding()
	 */
	public void setOverrideHeaderCharacterEncoding(
			boolean overrideHeaderCharacterEncoding)
	{
		this.overrideHeaderCharacterEncoding = overrideHeaderCharacterEncoding;
	}
}
