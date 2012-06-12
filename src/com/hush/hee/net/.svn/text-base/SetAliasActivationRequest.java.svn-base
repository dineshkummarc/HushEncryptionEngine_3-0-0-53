/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.hee.net;

public class SetAliasActivationRequest extends Request
{
	public String alias;
	public boolean active;
	public final String ACT_REQ = "setAliasActivationRequest";
	public final String ACT_RES = "setAliasActivationResponse";

	public SetAliasActivationRequest(String alias, boolean active)
	{
		this.alias = alias;
		this.active = active;
	}

	public String getType()
	{
		return "setAliasActivation";
	}

	public void sendRequest()
	{
		connection.write("<" + ACT_REQ + " alias=\"" + alias + "\"");
		connection.write(" active=\"" + (active ? "true" : "false") + "\"");
		connection.write("/>");
	}
}