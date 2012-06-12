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

public class SetPassphraseExpirationTimeRequest extends Request
{
	// The alias (in request)
	private String alias;

	public SetPassphraseExpirationTimeRequest(String alias)
	{
		this(alias, -1);
	}

	public SetPassphraseExpirationTimeRequest(
		String alias,
		long expirationTime)
	{
		this.alias = alias;
		this.passphraseExpirationTime = expirationTime;
	}

	public String getType()
	{
		return "setPassphraseExpirationTime";
	}

	private long passphraseExpirationTime;

	public void sendRequest()
	{

		connection.write("<setPassphraseExpirationTimeRequest");
		connection.write(" alias=\"" + alias + "\"");
		if (passphraseExpirationTime >= 0)
			connection.write(
				" passphraseExpirationTime=\""
					+ passphraseExpirationTime
					+ "\"");
		connection.write("/>");
	}
}