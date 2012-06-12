/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.hee.net;

public class PuKDeletionRequest extends Request
{
	private String alias;

	public String getType()
	{
		return "publicKeyDeletion";
	}

	public PuKDeletionRequest(String iAlias)
	{
		super();

		alias = iAlias;
	}

	public void sendRequest()
	{
		connection.write("<publicKeyDeletionRequest alias=\"" + alias + "\"/>");
	}
}