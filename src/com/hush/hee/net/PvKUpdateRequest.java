/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.hee.net;

import com.hush.hee.keyserver.PrivateKey;
import com.hush.hee.net.Request;

import java.lang.String;

public class PvKUpdateRequest extends Request
{
	private String nonce;
	private String privateAlias;
	public PrivateKey[] privateKeys;
	public String randomSeedPackage;
	private String newPrivateAlias;
	private Boolean addKeys;

	public String getType()
	{
		return "privateKeyUpdate";
	}

	public PvKUpdateRequest(
			String privateAlias,
			String newPrivateAlias,
			PrivateKey[] privateKeys,
			String randomSeed,
			Boolean addKeys,
			String nonce)
	{
		super();
		this.privateAlias = privateAlias;
		this.newPrivateAlias = newPrivateAlias;
		this.privateKeys = privateKeys;
		this.randomSeedPackage = randomSeed;
		this.addKeys = addKeys;
	}

	public void sendRequest()
	{
		String request = "<privateKeyUpdateRequest privateAlias=\""
				+ privateAlias + "\"";
		if (newPrivateAlias != null)
			request += " newPrivateAlias=\"" + newPrivateAlias + "\"";
		
		if (addKeys != null )
			request += " addKey=\"" + addKeys.toString() + "\"";
		
		request += " Nonce=\"" + nonce + "\">";

		if (privateKeys != null)
		{
			for (int i = 0; i < privateKeys.length; i++)
			{
				request += "<privateKeyPackage";
				if (privateKeys[i].getIndex() != null)
				{
					request += " index=\"" + privateKeys[i].getIndex() + "\"";
				}
				request += ">";
				request += "<![CDATA["
						+ privateKeys[i].getEncryptedPrivateKey() + "]]>"
						+ "</privateKeyPackage>";
			}
		}

		if (randomSeedPackage != null)
		{
			request += "<randomSeedPackage>" + "<![CDATA[" + randomSeedPackage
					+ "]]>" + "</randomSeedPackage>";
		}

		request += "</privateKeyUpdateRequest>";
		
		connection.write(request);
	}
}