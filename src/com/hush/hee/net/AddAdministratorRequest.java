/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.hee.net;

public class AddAdministratorRequest extends Request
{
	private String alias;
	private String customerID;

	public AddAdministratorRequest(String customerID, String alias)
	{
		this.customerID = customerID;
		this.alias = alias;
	}

	public String getType()
	{
		return "addAdministrator";
	}

	public void sendRequest()
	{
		connection.write("<");
		connection.write(getType() + REQUEST);
		connection.write(" customerID=\"" + customerID + "\"");
		connection.write(" alias=\"" + alias + "\"");
		connection.write("/>");
	}
}