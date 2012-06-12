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

public class AdkAcceptanceLookupRequest extends Request
{
	private String domain;
	private String customerID;
	private Vector domains = new Vector();

	public AdkAcceptanceLookupRequest(String domain)
	{
		this.domain = domain;
	}

	public String getType()
	{
		return "adkAcceptanceLookup";
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

			if (!"acceptFor".equalsIgnoreCase(tk.name))
			{
				break;
			}

			domains.addElement(
				((String) tk.htAttr.get("domain")).trim().toLowerCase());
		}
		lastLine = currentLine;
	}

	public String[] getDomains()
	{
		String[] domainStrings = new String[domains.size()];
		domains.copyInto(domainStrings);
		return domainStrings;
	}
}