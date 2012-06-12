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

public class PuKActivationRequest extends Request
{
	private String activationCode;
	private String alias;
	private int check;
	private String preActivationCode;

	public PuKActivationRequest(String iAlias, String iActivationCode)
	{
		super();

		alias = iAlias;
		activationCode = iActivationCode;
		check = 0;
	}

	public PuKActivationRequest(
		String iAlias,
		String iActivationCode,
		String iPreActivationCode)
	{
		super();

		alias = iAlias;
		activationCode = iActivationCode;
		preActivationCode = iPreActivationCode;

		check = 1;
	}

	public String getType()
	{
		return "publicKeyActivation";
	}

	public void sendRequest()
	{
		if (check == 0)
		{
			connection.write(
				"<publicKeyActivationRequest alias=\""
					+ alias
					+ "\" activationCode=\""
					+ activationCode
					+ "\"/>");
		}
		else
		{
			connection.write(
				"<publicKeyActivationRequest alias=\""
					+ alias
					+ "\" activationCode=\""
					+ activationCode
					+ "\" preActivationCode=\""
					+ preActivationCode
					+ "\"/>");
		}
	}
}