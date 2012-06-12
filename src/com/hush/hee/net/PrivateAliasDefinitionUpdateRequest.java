package com.hush.hee.net;

import java.io.IOException;

import com.hush.hee.IteratedAndSaltedPrivateAliasDefinition;
import com.hush.hee.KeyStoreException;
import com.hush.hee.BadRequestException;

public class PrivateAliasDefinitionUpdateRequest extends Request
{
	
	private String alias;
	private IteratedAndSaltedPrivateAliasDefinition privateAliasDefinition;

	public PrivateAliasDefinitionUpdateRequest(String alias,
			String privateAliasDefinition) throws BadRequestException
	{
		this.alias = alias;
		this.privateAliasDefinition = IteratedAndSaltedPrivateAliasDefinition
				.parseContents(privateAliasDefinition);
	}

	public String getType()
	{
		return "privateAliasDefinitionUpdate";
	}

	public void sendRequest()
	{
		connection.write("<" + getType() + "Request");
		connection.write(" alias=\"" + alias + "\"");
		connection.write(privateAliasDefinition.toStringNoHeader());
		connection.write("/>");
	}

	public void processBody() throws IOException, KeyStoreException
    {
    }
}
