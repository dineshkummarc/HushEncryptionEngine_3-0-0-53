/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.hee.net;

import com.hush.hee.BadRequestException;
import com.hush.hee.IteratedAndSaltedPrivateAliasDefinition;
import com.hush.hee.keyserver.PublicKey;
import com.hush.hee.net.Request;

import java.lang.String;

public class PuKUpdateRequest extends Request
{
	private String alias;
	private String preActivationCode;
	private PublicKey[] publicKeys;
	private String customerID;
	private String applicationID;
	private String passphraseComponent;
	private IteratedAndSaltedPrivateAliasDefinition privateAliasDefinition;
    private String encryptionMethod;
    
    private final static String ENCRYPTION_METHOD_NORMAL = "Normal";
    private final static String ENCRYPTION_METHOD_WEB = "Web";
    private final static String ENCRYPTION_METHOD_NONE = "None";

	public String getType()
	{
		return "publicKeyUpdate";
	}

    public PuKUpdateRequest(String iAlias, PublicKey[] iPublicKeys,
			String iPreActivationCode, String iCustomerID,
			String iApplicationID, String iPrivateAliasDefinition,
			String iEncryptionMethod, String iPassphraseComponent)
			throws BadRequestException
	{
		alias = iAlias;
		publicKeys = iPublicKeys;
		preActivationCode = iPreActivationCode;
		customerID = iCustomerID;
		applicationID = iApplicationID;
		if (iPrivateAliasDefinition != null)
		{
			privateAliasDefinition = IteratedAndSaltedPrivateAliasDefinition
					.parseContents(iPrivateAliasDefinition);
		}
		passphraseComponent = iPassphraseComponent;
		if (iEncryptionMethod != null)
		{
			if (iEncryptionMethod.equals(ENCRYPTION_METHOD_NONE)
					|| iEncryptionMethod.equals(ENCRYPTION_METHOD_NORMAL)
					|| iEncryptionMethod.equals(ENCRYPTION_METHOD_WEB))
			{
				encryptionMethod = iEncryptionMethod;
			}
			else
			{
				throw new IllegalArgumentException(
						"Encryption method must be one of "
								+ ENCRYPTION_METHOD_NONE + ", "
								+ ENCRYPTION_METHOD_NORMAL + ", "
								+ ENCRYPTION_METHOD_WEB);
			}
		}
	}

	public void sendRequest()
	{
		connection.write(
			"<publicKeyUpdateRequest alias=\""
				+ alias
				+ "\" customerID=\""
				+ customerID
				+ "\" applicationID=\""
				+ applicationID
				+ "\"");

		if (preActivationCode != null)
			connection.write(
				" preActivationCode=\"" + preActivationCode + "\"");
        
        if (encryptionMethod != null)
            connection.write(
                " encryptionMethod=\"" + encryptionMethod + "\"");

		connection.write(">");
		
		for(int i=0; i<publicKeys.length; i++)
		{
			connection.write("<publicKeyPackage keyID=\"" + publicKeys[i].getKeyID() + "\">");
			connection.write("<![CDATA[" + publicKeys[i].getKey() + "]]>");
			connection.write("</publicKeyPackage>");
		}

		if (passphraseComponent != null)
		{
			connection.write("<passphraseComponent>");
			connection.write("<![CDATA[");
			connection.write(passphraseComponent);
			connection.write("]]>");
			connection.write("</passphraseComponent>");
		}

		if (privateAliasDefinition != null)
		{
			connection.write(privateAliasDefinition.toStringNoHeader());
		}
		
		connection.write("</publicKeyUpdateRequest>");
	}

}