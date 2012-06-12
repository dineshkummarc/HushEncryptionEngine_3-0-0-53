/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.hee.net;

/**
 * Insert the type's description here.
 * Creation date: (05/04/2001 17:44:29)
 * @author:
 */

public class SavePassphraseComponentRequest extends Request
{
	public String passphraseComponent;
	public String alias;
	public final String SAVE_PFC_RES = "savePassphraseComponentResponse";
	public final String SAVE_PFC_REQ = "savePassphraseComponentRequest";

	public SavePassphraseComponentRequest(
		String alias,
		String passphraseComponent)
	{
		this.alias = alias;
		this.passphraseComponent = passphraseComponent;
	}

	public String getType()
	{
		return "savePassphraseComponent";
	}

	public void sendRequest()
	{
		connection.write("<");
		connection.write(SAVE_PFC_REQ);
		connection.write(" alias=\"" + alias + "\">");
		connection.write("<passphraseComponent><![CDATA[");
		connection.write(passphraseComponent);
		connection.write("]]></passphraseComponent>");

		connection.write("</" + SAVE_PFC_REQ + ">");
	}
}