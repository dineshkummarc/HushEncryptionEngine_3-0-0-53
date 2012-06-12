/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.util;

import java.util.Vector;

public class ArrayTools
{
	public static boolean equals(byte[] array1, byte[] array2)
	{
		return equals(array1, 0, array2, 0, array1.length);
	}

	public static boolean equals(
		byte[] array1,
		int offset1,
		byte[] array2,
		int offset2,
		int length)
	{
		if (array1 == null)
		{
			if (array2 == null)
				return true;
			else
				return false;
		}
		if (array1.length - offset1 < length)
			return false;
		if (array2.length - offset2 < length)
			return false;
		for (int x = 0; x < length; x++)
		{
			if (array1[x + offset1] != array2[x + offset2])
				return false;
		}
		return true;
	}

	public static byte[] concatenate(byte[][] byteArrays)
	{
		int totalLength = 0;
		for (int x = 0; x < byteArrays.length; x++)
		{
			totalLength += byteArrays[x].length;
		}
		byte[] result = new byte[totalLength];
		int currentPosition = 0;
		for (int x = 0; x < byteArrays.length; x++)
		{
			System.arraycopy(
				byteArrays[x],
				0,
				result,
				currentPosition,
				byteArrays[x].length);
			currentPosition += byteArrays[x].length;
		}
		return result;
	}

	public static byte[] trim(byte[] toTrim)
	{
		int trimPos = -1;
		for (int x = 0; x < toTrim.length; x++)
		{
			if ((toTrim[x] >= 0 && toTrim[x] < 33) || toTrim[x] == 127)
			{
				if (trimPos == -1)
					trimPos = x;
			}
			else
				trimPos = -1;
		}
		if (trimPos == -1)
			return toTrim;
		else
		{
			byte[] trimmed = new byte[trimPos];
			System.arraycopy(toTrim, 0, trimmed, 0, trimPos);
			return trimmed;
		}
	}

	public static void wipe(Object in)
	{
		if ( in instanceof byte[] )
		{
			byte[] b = (byte[])in;
			for (int x = 0; x < b.length; x++)
				b[x] = 0;
		}
		else if ( in instanceof char[] )
		{
			char[] b = (char[])in;
			for (int x = 0; x < b.length; x++)
				b[x] = 0;
		}
	}

	/**
	 * Returns the intersection between several byte arrays.
	 *
	 * The order of the elements in the intersection will correspond
	 * to the order of the elements in the last array.
	 *
	 * @param arrayList a list of arrays to intersect
	 */
	public static byte[] intersection(byte[][] arrayList)
	{
		Vector elements = new Vector();
		for (int x = 0; x < arrayList[0].length; x++)
		{
			elements.addElement(new Byte(arrayList[0][x]));
		}
		for (int x = 1; x < arrayList.length; x++)
		{
			Vector tmpElements = new Vector();
			for (int y = 0; y < arrayList[x].length; y++)
			{
				if (elements.indexOf(new Byte(arrayList[x][y])) != -1)
				{
					tmpElements.addElement(new Byte(arrayList[x][y]));
				}
			}
			elements = tmpElements;
		}
		byte[] retVal = new byte[elements.size()];
		for (int x = 0; x < elements.size(); x++)
		{
			retVal[x] = ((Byte) elements.elementAt(x)).byteValue();
		}
		return retVal;
	}
	
	public static boolean contains(char[] list, char character)
	{
		for(int i = 0; i < list.length; i++)
			if (list[i] == character)
				return true;
		return false;
	}
}
