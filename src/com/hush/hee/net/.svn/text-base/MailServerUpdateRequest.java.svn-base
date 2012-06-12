/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.hee.net;

import com.hush.hee.net.Request;

import java.lang.String;

public class MailServerUpdateRequest extends Request
{
	private String alias;
	private String mailserverPassword;

	// if a record alreaday exists, use mailserverPassword for
	// authentication, and newMailserverPassword to change the password
	public String newMailserverPassword;

	public MailServerUpdateRequest(String iAlias, String iMailserverPassword,
			String iNewMailserverPassword)
	{
		super();
		if (iAlias == null || iNewMailserverPassword == null
				|| iMailserverPassword == null )
			throw new IllegalArgumentException("Required parameters are null");
		alias = iAlias;
		mailserverPassword = iMailserverPassword;
		newMailserverPassword = iNewMailserverPassword;
	}

	public String getType()
	{
		return "mailserverUpdate";
	}

	public void sendRequest()
	{
		connection.write("<mailserverUpdateRequest alias=\"" + alias
				+ "\" mailserverPassword=\"" + mailserverPassword + "\"");
		connection.write(" newMailserverPassword=\""
					+ newMailserverPassword);
		connection.write("\"/>");
	}
}