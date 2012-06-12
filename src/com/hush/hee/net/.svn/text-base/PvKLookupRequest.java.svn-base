/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.hee.net;

import com.hush.hee.KeyStoreException;

import java.util.Date;
import java.util.Vector;
import com.hush.hee.keyserver.PrivateKey;
import com.hush.util.Logger;

import java.io.IOException;


public class PvKLookupRequest extends Request
{
	private String nonce;

	// The private alais
	private String privateAlias;
	
	private Boolean getAllKeys;

	// Private keys
	private PrivateKey[] privateKeys;

	// The random seed package
	private String randomSeedPackage;

	// The last time the key was accessed
	private Date lastAccessTime = null;

	private final String PVK_PACKAGE = "privateKeyPackage";
	private final String PVK_PACKAGE_END = "/privateKeyPackage";
	private final String RANDOM_SEED_PACKAGE = "randomSeedPackage";
	private final String RANDOM_SEED_PACKAGE_END = "/randomSeedPackage";

	public String getType()
	{
		return "privateKeyLookup";
	}

	public PvKLookupRequest(String iPrivateAlias, Boolean
			iGetAllKeys, String nonce)
	{
		super();

		privateAlias = iPrivateAlias;
		getAllKeys = iGetAllKeys;
		this.nonce = nonce;
	}

	public Date getLastAccessTime()
	{
		return lastAccessTime;
	}

	public PrivateKey[] getPrivateKeys()
	{
		return privateKeys;
	}

	public String getRandomSeed()
	{
		return randomSeedPackage;
	}

	public void processBody() throws IOException, KeyStoreException
	{

		try
		{
			long lastAccessTimeLong =
				Long.parseLong((String) attributes.get(LAST_ACCESS_TIME));
			if ( lastAccessTimeLong > 0 )
				lastAccessTime = new Date(lastAccessTimeLong * 1000);
		}
		catch (NumberFormatException e)
		{
			Logger.log(this, Logger.WARNING,
				"Warning, private key last access time is not in a valid format");
		}

		Tokeniser tk;
		
		// the current line to parse
		String currentLine;
		
		currentLine = connection.readLine();

		tk = new Tokeniser(currentLine);

		if (!PVK_PACKAGE.equalsIgnoreCase(tk.name))
			throw new KeyStoreException("Expecting: " + PVK_PACKAGE);

		Vector keys = new Vector();
		
		while ( !RANDOM_SEED_PACKAGE.equalsIgnoreCase(tk.name))
		{
			if (!PVK_PACKAGE.equalsIgnoreCase(tk.name))
				throw new KeyStoreException("Expecting: " + PVK_PACKAGE);
		
			String index = (String) tk.htAttr.get(INDEX);
		
			String pvkPackage = CDATAReader.process(connection);

			PrivateKey key = new PrivateKey();
			
			key.setEncryptedPrivateKey(pvkPackage);
			key.setIndex(index);
			keys.addElement(key);
			
			currentLine = connection.readLine();
			tk = new Tokeniser(currentLine);

			if (!PVK_PACKAGE_END.equalsIgnoreCase(tk.name))
				throw new KeyStoreException("Expecting: " + PVK_PACKAGE_END);
		
			currentLine = connection.readLine();
			tk = new Tokeniser(currentLine);
		}
		privateKeys = new PrivateKey[keys.size()];
		keys.copyInto(privateKeys);
		
		if (!RANDOM_SEED_PACKAGE.equalsIgnoreCase(tk.name))
			throw new KeyStoreException("Expecting: " + RANDOM_SEED_PACKAGE);

		randomSeedPackage = CDATAReader.process(connection);

		currentLine = connection.readLine();
		tk = new Tokeniser(currentLine);

		if (!RANDOM_SEED_PACKAGE_END.equalsIgnoreCase(tk.name))
			throw new KeyStoreException(
				"Expecting: " + RANDOM_SEED_PACKAGE_END);

	}

	public void sendRequest()
	{
		connection.write("<privateKeyLookupRequest privateAlias=\""
				+ privateAlias + "\"");
		if (getAllKeys != null)
			connection.write(" getAllKeys=\"" + getAllKeys.toString() + "\"");
		connection.write(" Nonce=\"" + nonce + "\"/>");
	}
}