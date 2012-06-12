package com.hush.hee.axbridge;

public class HushEncryptionEngineAxbridge extends com.hush.hee.axbridge.HushEncryptionEngineBase
{
	public int checkCanEncrypt(com.hush.hee.axbridge.SecureMessage secureMessage, com.hush.hee.axbridge.CanEncryptResult result)
	{
		try
		{
			if ( secureMessage == null ) return ERROR_NULL_ARGUMENT;
			if ( result == null ) return ERROR_NULL_ARGUMENT;
			getDelegate().checkCanEncrypt(secureMessage, result);
			return ERROR_SUCCESS;
		}
		catch(Throwable t)
		{
			return this.processThrowable(t);
		}
	}

	public int decryptFileToFile(java.lang.String sourceFilePath, java.lang.String targetFilePath)
	{
		try
		{
			if ( sourceFilePath == null ) return ERROR_NULL_ARGUMENT;
			if ( targetFilePath == null ) return ERROR_NULL_ARGUMENT;
			getDelegate().decryptFileToFile(sourceFilePath, targetFilePath);
			return ERROR_SUCCESS;
		}
		catch(Throwable t)
		{
			return this.processThrowable(t);
		}
	}

	public int decryptFile(java.lang.String sourceFilePath)
	{
		try
		{
			if ( sourceFilePath == null ) return ERROR_NULL_ARGUMENT;
			getDelegate().decryptFile(sourceFilePath);
			return ERROR_SUCCESS;
		}
		catch(Throwable t)
		{
			return this.processThrowable(t);
		}
	}

	public int decryptText(java.lang.String text, com.hush.hee.axbridge.StringHolder result)
	{
		try
		{
			if ( text == null ) return ERROR_NULL_ARGUMENT;
			if ( result == null ) return ERROR_NULL_ARGUMENT;
			getDelegate().decryptText(text, result);
			return ERROR_SUCCESS;
		}
		catch(Throwable t)
		{
			return this.processThrowable(t);
		}
	}

	public int encryptFileToFile(java.lang.String sourceFilePath, java.lang.String targetFilePath, com.hush.hee.axbridge.SecureMessage secureMessage)
	{
		try
		{
			if ( sourceFilePath == null ) return ERROR_NULL_ARGUMENT;
			if ( targetFilePath == null ) return ERROR_NULL_ARGUMENT;
			if ( secureMessage == null ) return ERROR_NULL_ARGUMENT;
			getDelegate().encryptFileToFile(sourceFilePath, targetFilePath, secureMessage);
			return ERROR_SUCCESS;
		}
		catch(Throwable t)
		{
			return this.processThrowable(t);
		}
	}

	public int encryptAndSignFileToFile(java.lang.String sourceFilePath, java.lang.String targetFilePath, com.hush.hee.axbridge.SecureMessage secureMessage)
	{
		try
		{
			if ( sourceFilePath == null ) return ERROR_NULL_ARGUMENT;
			if ( targetFilePath == null ) return ERROR_NULL_ARGUMENT;
			if ( secureMessage == null ) return ERROR_NULL_ARGUMENT;
			getDelegate().encryptAndSignFileToFile(sourceFilePath, targetFilePath, secureMessage);
			return ERROR_SUCCESS;
		}
		catch(Throwable t)
		{
			return this.processThrowable(t);
		}
	}

	public int encrypt(com.hush.hee.axbridge.SecureMessage secureMessage)
	{
		try
		{
			if ( secureMessage == null ) return ERROR_NULL_ARGUMENT;
			getDelegate().encrypt(secureMessage);
			return ERROR_SUCCESS;
		}
		catch(Throwable t)
		{
			return this.processThrowable(t);
		}
	}

	public int getAdditionalDecryptionKeyAcceptanceList(java.lang.String domain, java.util.Set additionalDecryptionKeyAcceptanceList)
	{
		try
		{
			if ( domain == null ) return ERROR_NULL_ARGUMENT;
			if ( additionalDecryptionKeyAcceptanceList == null ) return ERROR_NULL_ARGUMENT;
			getDelegate().getAdditionalDecryptionKeyAcceptanceList(domain, additionalDecryptionKeyAcceptanceList);
			return ERROR_SUCCESS;
		}
		catch(Throwable t)
		{
			return this.processThrowable(t);
		}
	}

	public int getAdditionalDecryptionKeyAliases(java.lang.String domain, java.util.Set additionalDecryptionKeyAliases)
	{
		try
		{
			if ( domain == null ) return ERROR_NULL_ARGUMENT;
			if ( additionalDecryptionKeyAliases == null ) return ERROR_NULL_ARGUMENT;
			getDelegate().getAdditionalDecryptionKeyAliases(domain, additionalDecryptionKeyAliases);
			return ERROR_SUCCESS;
		}
		catch(Throwable t)
		{
			return this.processThrowable(t);
		}
	}

	public int isPassphraseExpired(com.hush.hee.axbridge.BooleanHolder expired)
	{
		try
		{
			if ( expired == null ) return ERROR_NULL_ARGUMENT;
			getDelegate().isPassphraseExpired(expired);
			return ERROR_SUCCESS;
		}
		catch(Throwable t)
		{
			return this.processThrowable(t);
		}
	}

	public int verifyFile(java.lang.String signer, java.lang.String filePath, java.lang.String signature, java.util.Set validSigners, java.util.Set invalidSigners)
	{
		try
		{
			if ( signer == null ) return ERROR_NULL_ARGUMENT;
			if ( filePath == null ) return ERROR_NULL_ARGUMENT;
			if ( signature == null ) return ERROR_NULL_ARGUMENT;
			if ( validSigners == null ) return ERROR_NULL_ARGUMENT;
			if ( invalidSigners == null ) return ERROR_NULL_ARGUMENT;
			getDelegate().verifyFile(signer, filePath, signature, validSigners, invalidSigners);
			return ERROR_SUCCESS;
		}
		catch(Throwable t)
		{
			return this.processThrowable(t);
		}
	}

	public int verifyCleartextSignedMessage(java.lang.String signer, java.lang.String signedMessage, java.util.Set validSigners, java.util.Set invalidSigners, com.hush.hee.axbridge.StringHolder signature)
	{
		try
		{
			if ( signer == null ) return ERROR_NULL_ARGUMENT;
			if ( signedMessage == null ) return ERROR_NULL_ARGUMENT;
			if ( validSigners == null ) return ERROR_NULL_ARGUMENT;
			if ( invalidSigners == null ) return ERROR_NULL_ARGUMENT;
			if ( signature == null ) return ERROR_NULL_ARGUMENT;
			getDelegate().verifyCleartextSignedMessage(signer, signedMessage, validSigners, invalidSigners, signature);
			return ERROR_SUCCESS;
		}
		catch(Throwable t)
		{
			return this.processThrowable(t);
		}
	}

	public int signFile(java.lang.String filePath, com.hush.hee.axbridge.StringHolder signature)
	{
		try
		{
			if ( filePath == null ) return ERROR_NULL_ARGUMENT;
			if ( signature == null ) return ERROR_NULL_ARGUMENT;
			getDelegate().signFile(filePath, signature);
			return ERROR_SUCCESS;
		}
		catch(Throwable t)
		{
			return this.processThrowable(t);
		}
	}

	public int signText(java.lang.String filePath, boolean detached, com.hush.hee.axbridge.StringHolder signature)
	{
		try
		{
			if ( filePath == null ) return ERROR_NULL_ARGUMENT;
			if ( signature == null ) return ERROR_NULL_ARGUMENT;
			getDelegate().signText(filePath, detached, signature);
			return ERROR_SUCCESS;
		}
		catch(Throwable t)
		{
			return this.processThrowable(t);
		}
	}

	public int authenticate(java.lang.String userAlias, java.lang.String passphrase)
	{
		try
		{
			if ( userAlias == null ) return ERROR_NULL_ARGUMENT;
			if ( passphrase == null ) return ERROR_NULL_ARGUMENT;
			getDelegate().authenticate(userAlias, passphrase);
			return ERROR_SUCCESS;
		}
		catch(Throwable t)
		{
			return this.processThrowable(t);
		}
	}

	public int setParameter(java.lang.String key, java.lang.String value)
	{
		try
		{
			if ( key == null ) return ERROR_NULL_ARGUMENT;
			if ( value == null ) return ERROR_NULL_ARGUMENT;
			getDelegate().setParameter(key, value);
			return ERROR_SUCCESS;
		}
		catch(Throwable t)
		{
			return this.processThrowable(t);
		}
	}

}