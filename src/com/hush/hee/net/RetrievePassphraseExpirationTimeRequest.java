/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.hee.net;

/**
 * Request to lookup a public key.
 *
 * @author      Declan Gallagher
 * @date        16th February, 2001
 * @version     Beta Version 2.0
 * @copyright   Copyright (c) 2001 by Hush Communications Corporation.
 *
 */
import com.hush.hee.net.Request;

import java.lang.String;

public class RetrievePassphraseExpirationTimeRequest extends Request
{
	// The alias (in request)
	public String alias;

	// The current line to be parsed
	public String currentLine;

	// XML Tags
	public final String PP_EXP_LOOKUP_RESPONSE =
		"retrievePassphraseExpirationTimeResponse";
	public final String PP_EXP_LOOKUP_RESPONSE_END =
		"/retrievePassphraseExpirationTimeResponse";
	public final String PP_EXP_TIME = "passphraseExpirationTime";

	public RetrievePassphraseExpirationTimeRequest(String alias)
	{
		this.alias = alias;
	}

	public String getType()
	{
		return "retrievePassphraseExpirationTime";
	}

	private long passphraseExpirationTime;

	public void processBody()
	{
		passphraseExpirationTime =
			Long.parseLong((String) attributes.get(PP_EXP_TIME));
	}

	/**
	 * Sends the well formed xml to the server.
	 * Creation date: (16/02/2001 15:29:11)
	 */
	public void sendRequest()
	{

		connection.write("<retrievePassphraseExpirationTimeRequest");
		connection.write(" alias=\"" + alias + "\"");
		connection.write("/>");
	}

	public long getPassphraseExpirationTime()
	{
		return passphraseExpirationTime;
	}

}