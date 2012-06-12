/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.util;

import java.util.Enumeration;
import java.util.StringTokenizer;
import java.util.Vector;

public class Conversions2
{

	/**
	 * A utility function for converting Vectors to Strings.
	 *
	 * @param v the Vector to convert
	 * @param separator the String that separates the elements in the return value
	 * @return a list of values separated by separator
	 */
	public static String vectorToString(Vector v, String separator)
	{
		if ( v == null ) return null;
		StringBuffer tempBuffer = new StringBuffer("");
		Enumeration e = v.elements();

		while (e.hasMoreElements())
		{
			if (tempBuffer.length() != 0)
			{
				tempBuffer.append(separator);
			}

			tempBuffer.append((String) e.nextElement());
		}

		return tempBuffer.toString();
	}

	/**
	 * A utility function for converting Strings to Vectors.
	 *
	 * @param list the list of values to convert.
	 * @param separator between values in the list.
	 * @param returnDelims a boolean set to true to return separators in Vector.
	 * @return a Vector constructed of the values in the list.
	 */
	public static Vector stringToVector(
		String list,
		String separator,
		boolean returnDelims)
	{
		if ( list == null ) return null;
		StringTokenizer t = new StringTokenizer(list, separator, returnDelims);
		Vector v = new Vector();

		while (t.hasMoreElements())
		{
			v.addElement(t.nextElement());
		}

		return v;
	}

	/**
	 * A utility function for converting a String to an array of Strings
	 *
	 * @param list the list of values to convert.
	 * @param separator between values in the list.
	 * @param returnDelims a boolean set to true to return separators in Vector.
	 * @return a String constructed of the values in the list.
	 */
	public static String[] stringToArray(
		String list,
		String separator,
		boolean returnDelims)
	{
		if ( list == null ) return null;
		Vector v = stringToVector(list, separator, returnDelims);
		String[] s = new String[v.size()];
		for (int x = 0; x < v.size(); x++)
		{
			s[x] = (String) v.elementAt(x);
		}
		return s;
	}
	
	/**
	 * A utility function for converting a String array to a String
	 * @param stringArray an array containing the items.
	 * @param separator the separator to appear between items.
	 * @return the list of items in a String.
	 */
	public static String stringArrayToString(
			String[] stringArray,
			String separator)
	{
		if ( stringArray == null ) return null;
		StringBuffer s = new StringBuffer();
		for (int i = 0; i < stringArray.length; i++)
		{
			s.append (stringArray[i]);
			if (i < stringArray.length - 1)
				s.append(separator);
		}
		return s.toString();
	}
	
	public static Vector arrayToVector(Object[] o)
	{
		if ( o == null ) return null;
		Vector v = new Vector();
		for(int i=0; i<o.length; i++)
			v.addElement(o[i]);
		return v;
	}
	
	public static String[] vectorToStringArray(Vector v)
	{
		if ( v == null ) return null;
		String[] s = new String[v.size()];
		v.copyInto(s);
		return s;
	}
}
