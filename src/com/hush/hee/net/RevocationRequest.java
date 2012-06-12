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
import com.hush.hee.net.Request;

import java.lang.String;

public class RevocationRequest extends Request
{
	public String alias;
	public String preActivationCode;
	public String keyID;
	public final String REV_REQ = "revocationRequest";
	public final String REV_RES = "revocationResponse";

	public RevocationRequest(
		String alias,
		String preActivationCode,
		String keyID)
	{
		this.alias = alias;
		this.preActivationCode = preActivationCode;
		this.keyID = keyID;
	}

	public String getType()
	{
		return "revocation";
	}

	public void sendRequest()
	{
		connection.write("<" + REV_REQ + " alias=\"" + alias + "\"");

		if (preActivationCode != null)
		{
			connection.write(
				" preActivationCode=\"" + preActivationCode + "\"");
		}

		if (keyID != null)
		{
			connection.write(" keyID=\"" + keyID + "\"");
		}

		connection.write("/>");
	}
}