package com.hush.hee;

import com.hush.hee.net.Tokeniser;

public class IteratedAndSaltedPrivateAliasDefinition
{
	public static final String XML_HEADER = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>";
	
	public static final String ITERATED_AND_SALTED_PRIVATE_ALIAS_DEFINITION = "iteratedHashWithAliasSaltPrivateAliasDefinition";

	public static final String S2K_PRIVATE_ALIAS_COUNT = "count";

	public static final String S2K_PRIVATE_ALIAS_HASH = "hashAlgorithm";

	public static final String S2K_PRIVATE_ALIAS_ENCODING = "encoding";
	
	private String hashAlgorithm;
	private Integer count;
	private String encoding;
	
	public IteratedAndSaltedPrivateAliasDefinition(
			String hashAlgorithm, Integer count, String encoding)
	{
		this.hashAlgorithm = hashAlgorithm;
		this.count = count;
		this.encoding = encoding;
	}

	public String toString()
	{
		return "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n"
				+ toStringNoHeader();
	}
				
	public String toStringNoHeader()
	{
		return "<" + ITERATED_AND_SALTED_PRIVATE_ALIAS_DEFINITION + " "
		+ S2K_PRIVATE_ALIAS_COUNT + "=\"" + count
		+ "\" " + S2K_PRIVATE_ALIAS_ENCODING + "=\""
		+ encoding + "\" " + S2K_PRIVATE_ALIAS_HASH
		+ "=\"" + hashAlgorithm + "\"/>";
	}
	
	public static IteratedAndSaltedPrivateAliasDefinition parseContents(
			String line) throws IllegalArgumentException
	{
		line = line.trim();
		if ( line.indexOf(XML_HEADER) == 0 )
		{
			line = line.substring(XML_HEADER.length());
			line = line.trim();
		}
		Tokeniser tk = new Tokeniser(line);
		if (!ITERATED_AND_SALTED_PRIVATE_ALIAS_DEFINITION
				.equalsIgnoreCase(tk.name))
			throw new IllegalArgumentException("Expecting: "
					+ ITERATED_AND_SALTED_PRIVATE_ALIAS_DEFINITION + " got "
					+ line);
		IteratedAndSaltedPrivateAliasDefinition def = new IteratedAndSaltedPrivateAliasDefinition(
				(String) tk.htAttr.get(S2K_PRIVATE_ALIAS_HASH), new Integer(
						(String) tk.htAttr.get(S2K_PRIVATE_ALIAS_COUNT)),
				(String) tk.htAttr.get(S2K_PRIVATE_ALIAS_ENCODING));
		return def;
	}

	public String getHashAlgorithm()
	{
		return hashAlgorithm;
	}

	public Integer getCount()
	{
		return count;
	}

	public String getEncoding()
	{
		return encoding;
	}
}
