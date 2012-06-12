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

public class RemoveAdministratorRequest extends Request
{
	public String customerID;
	public String alias;
	public final String REMOVE_ADMIN_RES = "removeAdministratorResponse";
	public final String REMOVE_ADMIN_REQ = "removeAdministratorRequest";

	public RemoveAdministratorRequest(String customerID, String alias)
	{
		super();

		this.customerID = customerID;
		this.alias = alias;
	}

	public String getType()
	{
		return "removeAdministrator";
	}

	public void sendRequest()
	{
		connection.write("<");
		connection.write(REMOVE_ADMIN_REQ);
		connection.write(" customerID=\"" + customerID + "\"");
		connection.write(" alias=\"" + alias + "\"");
		connection.write("/>");
	}
}