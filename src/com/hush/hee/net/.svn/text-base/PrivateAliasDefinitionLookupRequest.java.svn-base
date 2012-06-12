package com.hush.hee.net;

import java.io.IOException;

import com.hush.hee.IteratedAndSaltedPrivateAliasDefinition;
import com.hush.hee.KeyStoreException;

public class PrivateAliasDefinitionLookupRequest extends Request
{
	
	private String alias;
	private String privateAliasDefinition;

	public PrivateAliasDefinitionLookupRequest(String alias)
	{
		this.alias = alias;
	}

	public String getType()
	{
		return "privateAliasDefinitionLookup";
	}

	public void sendRequest()
	{
		connection.write("<" + getType() + "Request");
		connection.write(" alias=\"" + alias + "\"");
		connection.write("/>");
	}

	public void processBody() throws IOException, KeyStoreException
    {
		String currentLine;
		Tokeniser tk;
        currentLine = connection.readLine();
        tk = new Tokeniser(currentLine);
        
        if (PRIVATE_ALIAS_DEFINITION.equalsIgnoreCase(tk.name) )
        	return;
        
        IteratedAndSaltedPrivateAliasDefinition definition
        	= IteratedAndSaltedPrivateAliasDefinition.parseContents(currentLine);
        
        privateAliasDefinition = definition.toString();
    }

	public String getPrivateAliasDefinition()
	{
		return privateAliasDefinition;
	}
}
