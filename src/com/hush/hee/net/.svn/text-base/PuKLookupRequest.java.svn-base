/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.hee.net;

import java.io.IOException;

import com.hush.hee.KeyStoreException;
import com.hush.hee.NotFoundException;

import java.util.Vector;
import com.hush.hee.keyserver.GeneratedPassword;
import com.hush.hee.keyserver.PublicKey;

public class PuKLookupRequest extends Request
{
    private String alias = null;

    private String keyID = null;
    
    private boolean includeAdks = false;
    
    private String encryptionMethod = null;
    
    private GeneratedPassword generatedPassword = null;

    private String aliasStatus;

    private PublicKey[] publicKeys;

    private boolean sharedSecret = false;
    
    private boolean notFound = false;

    private static final String PUK_PACKAGE = "publicKeyPackage";

    private static final String PUK_PACKAGE_END = "/publicKeyPackage";

    private static final String SHARED_SECRET = "sharedSecret";
    
    private static final String ENCRYPTION_METHOD = "encryptionMethod";
    
    private static final String GENERATED_PASSWORD = "generatedPassword";
    
    private static final String GENERATED_PASSWORD_END = "/generatedPassword";

	private static final String GENERATED_PASSWORD_BODY_TEMPLATE = "generatedPasswordBodyTemplate";

	private static final String GENERATED_PASSWORD_SUBJECT_TEMPLATE = "generatedPasswordSubjectTemplate";
	
	private static final String GENERATED_PASSWORD_BODY_TEMPLATE_END = "/generatedPasswordBodyTemplate";

	private static final String GENERATED_PASSWORD_SUBJECT_TEMPLATE_END = "/generatedPasswordSubjectTemplate";
    
    private static final String METHOD = "method";
    
    private static final String RECIPIENT = "recipient";

    private static final String KEY_ID = "keyID";
    
    private static final String IS_ADK = "isAdk";
    
    private static final String SUPPORT_ADKS = "includeAdks";
    
    public String getType()
    {
        return "publicKeyLookup";
    }

    public PuKLookupRequest(String iAlias, String keyID, boolean includeAdks)
    {
        if (iAlias != null && !"".equals(iAlias.trim()))
            this.alias = iAlias.trim().toLowerCase();
        if (keyID != null && !"".equals(keyID.trim()))
            this.keyID = keyID.trim().toLowerCase();
        this.includeAdks = includeAdks;
    }

    public PublicKey[] getPublicKeys()
    {
        return publicKeys;
    }

    public void processBody() throws IOException, KeyStoreException
	{
		Object sharedSecretObj = attributes.get(SHARED_SECRET);

		if (sharedSecretObj != null)
			sharedSecret = Boolean.valueOf((String) sharedSecretObj)
					.booleanValue();

		alias = (String) attributes.get(ALIAS);
		aliasStatus = (String) attributes.get(ALIAS_STATUS);
		encryptionMethod = (String) attributes.get(ENCRYPTION_METHOD);

		String currentLine = connection.readLine();
		Tokeniser tk = new Tokeniser(currentLine);
		
		Vector keys = new Vector();
		
		while (PUK_PACKAGE.equalsIgnoreCase(tk.name))
		{
			String keyID = (String) tk.htAttr.get(KEY_ID);
			String isAdk = (String) tk.htAttr.get(IS_ADK);
			String pukBlock = CDATAReader.process(connection);
			PublicKey publicKey = new PublicKey();
			publicKey = new PublicKey();
			publicKey.setKeyID(keyID);
			publicKey.setKey(pukBlock);
			
			if ( isAdk != null && "true".equals(isAdk) )
			{
				publicKey.setIsAdk(true);
			}
			
			keys.addElement(publicKey);
			
			currentLine = connection.readLine();
			tk = new Tokeniser(currentLine);
			if (!PUK_PACKAGE_END.equalsIgnoreCase(tk.name))
				throw new KeyStoreException("Expecting: " + PUK_PACKAGE_END);
		
			currentLine = connection.readLine();
			tk = new Tokeniser(currentLine);
		}
		
		publicKeys = new PublicKey[keys.size()];
		keys.copyInto(publicKeys);

		if (GENERATED_PASSWORD.equalsIgnoreCase(tk.name))
		{
			if (generatedPassword != null)
			{
				throw new KeyStoreException(
						"Not expected two generated passwords");
			}
			String method = (String) tk.htAttr.get(METHOD);
			String recipient = (String) tk.htAttr.get(RECIPIENT);
			generatedPassword = new GeneratedPassword();
			generatedPassword.setMethod(method);
			generatedPassword.setPasswordRecipient(recipient);
			if ( "Email".equals(method) )
			{
				currentLine = connection.readLine();
				tk = new Tokeniser(currentLine);
				if (!GENERATED_PASSWORD_SUBJECT_TEMPLATE.equals(tk.name))
				{
					throw new KeyStoreException(
							"Expected: " + GENERATED_PASSWORD_SUBJECT_TEMPLATE);
				}
				generatedPassword.setEmailSubjectTemplate(CDATAReader.process(connection));
				currentLine = connection.readLine();
				tk = new Tokeniser(currentLine);
				if (!GENERATED_PASSWORD_SUBJECT_TEMPLATE_END.equals(tk.name))
				{
					throw new KeyStoreException(
							"Expected: " + GENERATED_PASSWORD_SUBJECT_TEMPLATE_END);
				}
				currentLine = connection.readLine();
				tk = new Tokeniser(currentLine);
				if (!GENERATED_PASSWORD_BODY_TEMPLATE.equals(tk.name))
				{
					throw new KeyStoreException(
							"Expected: " + GENERATED_PASSWORD_BODY_TEMPLATE);
				}
				generatedPassword.setEmailBodyTemplate(CDATAReader.process(connection));
				currentLine = connection.readLine();
				tk = new Tokeniser(currentLine);
				if (!GENERATED_PASSWORD_BODY_TEMPLATE_END.equals(tk.name))
				{
					throw new KeyStoreException("Expected: "
							+ GENERATED_PASSWORD_BODY_TEMPLATE_END);
				}
				currentLine = connection.readLine();
				tk = new Tokeniser(currentLine);
				if (!GENERATED_PASSWORD_END.equals(tk.name))
				{
					throw new KeyStoreException("Expected: "
							+ GENERATED_PASSWORD_END);
				}
			}
		}
		else
		{
			lastLine = currentLine;
		}
    }

    public void sendRequest()
    {
        connection.write("<publicKeyLookupRequest");
        if (alias != null)
        {
            connection.write(" alias=\"" + alias + "\"");
        }
        if (keyID != null)
        {
            connection.write(" " + KEYID + "=\"" + keyID + "\"");
        }
        if ( includeAdks )
        {
        	connection.write(" " + SUPPORT_ADKS + "=\"true\"");
        }
        connection.write("/>");
    }

    public String getEncryptionMethod()
    {
    	return encryptionMethod;
    }
    
    public GeneratedPassword getGeneratedPassword()
    {
    	return generatedPassword;
    }
    
    public boolean getSharedSecret()
    {
        return sharedSecret;
    }

    public String getAlias()
    {
        return alias;
    }

    public boolean isActive()
    {
        return ALIAS_STATUS_ACTIVE.equals(aliasStatus);
    }

    public boolean isPreActivated()
    {
        return ALIAS_STATUS_PRE_ACTIVATED.equals(aliasStatus);
    }

    public boolean isAwaitingActivationEmail()
    {
        return ALIAS_STATUS_AWAITING_ACTIVATION_EMAIL.equals(aliasStatus);
    }
    
	protected void handleNotFound() throws NotFoundException
	{
		notFound = true;
	}
	
	public boolean getNotFound()
	{
		return notFound;
	}
}