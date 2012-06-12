package com.hush.hee;

public class CanEncryptResult
{
	private String[] aliasesWithEncryptionMethod;

	private String[] aliasesWithNoEncryptionMethod;;

	private String[] deniedAliases;

	public CanEncryptResult(String[] aliasesWithEncryptionMethod,
			String[] aliasesWithNoEncryptionMethod, String[] deniedAliases)
	{
		this.aliasesWithEncryptionMethod = aliasesWithEncryptionMethod;
		this.aliasesWithNoEncryptionMethod = aliasesWithNoEncryptionMethod;
		this.deniedAliases = deniedAliases;
	}

	public String[] getAliasesWithEncryptionMethod()
	{
		return aliasesWithEncryptionMethod == null ? new String[0]
				: aliasesWithEncryptionMethod;
	}

	public String[] getAliasesWithNoEncryptionMethod()
	{
		return aliasesWithNoEncryptionMethod == null ? new String[0]
				: aliasesWithNoEncryptionMethod;
	}

	public String[] getDeniedAliases()
	{
		return deniedAliases == null ? new String[0] : deniedAliases;
	}

	public boolean getCanEncrypt()
	{
		return deniedAliases.length == 0
				&& aliasesWithNoEncryptionMethod.length == 0;
	}

	public void setAliasesWithEncryptionMethod(
			String[] aliasesWithEncryptionMethod)
	{
		this.aliasesWithEncryptionMethod = aliasesWithEncryptionMethod;
	}

	public void setAliasesWithNoEncryptionMethod(
			String[] aliasesWithNoEncryptionMethod)
	{
		this.aliasesWithNoEncryptionMethod = aliasesWithNoEncryptionMethod;
	}

	public void setDeniedAliases(String[] deniedAliases)
	{
		this.deniedAliases = deniedAliases;
	}
}
