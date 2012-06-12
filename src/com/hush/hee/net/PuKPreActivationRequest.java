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

public class PuKPreActivationRequest extends Request
{
	private String alias;
	private String preActivationCode;

	public String getType()
	{
		return "publicKeyPreActivation";
	}

	public PuKPreActivationRequest(
		String alias,
		String preActivationCode,
		int trustLevel)
	{
		super();
		this.alias = alias;
		this.preActivationCode = preActivationCode;
	}

	public void sendRequest()
	{
		connection.write("<");
		connection.write("publicKeyPreActivationRequest");
		connection.write(" alias=\"" + alias + "\"");
		connection.write(" preActivationCode=\"" + preActivationCode + "\"");
		connection.write("/>");
	}
}