/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.hee.net;

import java.io.IOException;
import java.util.Vector;

import com.hush.hee.KeyStoreException;

public class AdkLookupRequest extends Request
{
	private String domain;
	private String customerID;
	private Vector adks = new Vector();

	public AdkLookupRequest(String domain)
	{
		this.domain = domain;
	}

	public String getType()
	{
		return "adkLookup";
	}

	public void sendRequest()
	{
		connection.write("<");
		connection.write(getType() + REQUEST);
		connection.write(" domain=\"" + domain + "\"");
		connection.write("/>");
	}

	public void processBody() throws IOException, KeyStoreException
	{
		String currentLine;
		while ((currentLine = connection.readLine()) != null)
		{
			Tokeniser tk = new Tokeniser(currentLine);

			if (!"adk".equalsIgnoreCase(tk.name))
			{
				break;
			}


			adks.addElement(
				((String) tk.htAttr.get("alias")).trim().toLowerCase());
		}
		lastLine = currentLine;

	}

	public String[] getAliases()
	{
		String[] adkStrings = new String[adks.size()];
		adks.copyInto(adkStrings);
		return adkStrings;
	}
}