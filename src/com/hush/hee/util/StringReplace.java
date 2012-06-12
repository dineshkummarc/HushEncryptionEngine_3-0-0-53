package com.hush.hee.util;

public class StringReplace
{
	public static String replace(String text, String find, String replace)
	{
		if (text == null || text.length() == 0)
			return "";
		if (find == null || find.length() == 0)
			throw new IllegalArgumentException("The String to be found can not be of zero length");
		if (replace == null)
			replace = "";
		
		StringBuffer newString = new StringBuffer();
		
		int start = 0;
		int found = 0;
		
		while ((found = text.indexOf(find, start)) >= 0)
		{
			newString.append(text.substring(start, found));
			newString.append(replace);
			start = found + find.length();
		}
		newString.append(text.substring(start));
		
		return newString.toString();
	}
}
