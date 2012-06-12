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
import java.io.IOException;

import com.hush.hee.KeyStoreException;

public class RetrievePassphraseComponentRequest extends Request
{
	public String customerID;
	public String alias;
	public final String RPC_REQ = "retrievePassphraseComponentRequest";
	public final String RPC_RES = "retrievePassphraseComponentResponse";
	public final String RPC_RES_END = "/retrievePassphraseComponentResponse";
	public final String PC = "passphraseComponent";
	public final String PC_END = "/passphraseComponent";
	public String passphraseComponent = null;

	public RetrievePassphraseComponentRequest(String alias)
	{
		super();
		this.alias = alias;
	}

	public String getType()
	{
		return "retrievePassphraseComponent";
	}

	public String getPassphraseComponent()
	{
		return passphraseComponent;
	}

	/**
	 * Parses the body of the xml and extracts the relavent
	 * data and assign it to the storage variables.
	 *
	 * Throws ProtocolException
	 */
	public void processBody() throws IOException, KeyStoreException
	{
		Tokeniser tk;
		StringBuffer strBuff;
		String currentLine = connection.readLine();

		// <passphraseComponent>
		tk = new Tokeniser(currentLine);

		if (!PC.equalsIgnoreCase(tk.name))
			throw new KeyStoreException("Expecting: " + PC);

		// Process the CDATA
		passphraseComponent = CDATAReader.process(connection);

		// </passphraseComponent>
		currentLine = connection.readLine();
		tk = new Tokeniser(currentLine);

		if (!PC_END.equalsIgnoreCase(tk.name))
			throw new KeyStoreException("Expecting: " + PC_END);

	}

	public void sendRequest()
	{
		connection.write("<");
		connection.write(RPC_REQ);
		connection.write(" alias=\"" + alias + "\"");
		connection.write("/>");
	}
}