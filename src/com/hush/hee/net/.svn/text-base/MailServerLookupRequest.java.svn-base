/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.hee.net;

import com.hush.hee.KeyStoreException;

import java.io.IOException;

public class MailServerLookupRequest extends Request
{
	private String alias;

	public final String MAIL_STORAGE_ADDRESS = "mailStorageAddress";

	public final String MAILSERVER_PASSWORD_PACKAGE =
		"mailserverPasswordPackage";
	public final String MAILSERVER_PASSWORD_PACKAGE_END =
		"/mailserverPasswordPackage";

	public final String MAILSERVER_UID = "mailserverUID";
	private String mailserverPasswordPackage;
	private String mailserverUID;
	private String mailStorageAddress;

	public MailServerLookupRequest(String a)
	{
		alias = a;
	}

	public String getMailserverPassword()
	{
		return mailserverPasswordPackage;
	}

	public String getMailserverUID()
	{
		return mailserverUID;
	}

	public String getMailStorageAddress()
	{
		return mailStorageAddress;
	}

	public String getType()
	{
		return "mailserverLookup";
	}

	public void processBody() throws IOException, KeyStoreException
	{
		mailStorageAddress = (String) attributes.get(MAIL_STORAGE_ADDRESS);
		mailserverUID = (String) attributes.get(MAILSERVER_UID);

		Tokeniser tk;

		String currentLine = connection.readLine();
		tk = new Tokeniser(currentLine);

		if (!MAILSERVER_PASSWORD_PACKAGE.equalsIgnoreCase(tk.name))
			throw new KeyStoreException(
				"Expecting: " + MAILSERVER_PASSWORD_PACKAGE);

		mailserverPasswordPackage = CDATAReader.process(connection);
		currentLine = connection.readLine();
		tk = new Tokeniser(currentLine);

		if (!MAILSERVER_PASSWORD_PACKAGE_END.equalsIgnoreCase(tk.name))
			throw new KeyStoreException(
				"Expecting: " + MAILSERVER_PASSWORD_PACKAGE_END);
	}

	public void sendRequest()
	{
		connection.write("<mailserverLookupRequest alias=\"" + alias + "\"/>");
	}
}