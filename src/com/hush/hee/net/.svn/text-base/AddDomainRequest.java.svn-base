/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.hee.net;

public class AddDomainRequest extends Request
{
	private String customerID;
	private String domain;
	private boolean requireActivationEmail;
	private boolean requirePreActivation;

	public AddDomainRequest(
		String domain,
		String customerID,
		boolean requireActivationEmail,
		boolean requirePreActivation)
	{
		this.customerID = customerID;
		this.domain = domain;
		this.requireActivationEmail = requireActivationEmail;
		this.requirePreActivation = requirePreActivation;
	}

	public String getType()
	{
		return "addDomain";
	}

	public void sendRequest()
	{
		connection.write(
			"<addDomainRequest "
				+ " domain=\""
				+ domain
				+ "\" customerID=\""
				+ customerID
				+ "\" requiresEmailActivation=\""
				+ new Boolean(requireActivationEmail).toString().toLowerCase()
				+ "\" requiresPreActivation=\""
				+ new Boolean(requirePreActivation).toString().toLowerCase()
				+ "\"/>");
	}
}