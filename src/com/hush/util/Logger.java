/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.util;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

public class Logger
{
	public static final int NONE = 0;
	public static final int ERROR = 1;
	public static final int WARNING = 2;
	public static final int INFO = 3;
	public static final int DEBUG = 4;
	public static final int VERBOSE = 5;
	
	private static int _logLevel = WARNING;

	private static LoggerDelegate logWrapper = null;
	
	public static void setLogLevel(int logLevel)
	{
		_logLevel = logLevel;
	}

	public static int getLogLevel()
	{
		return _logLevel;
	}

	public static void log(Object source, int level,
		String message, Throwable throwable)
	{
		if ( logWrapper != null )
		{
			logWrapper.log(source, level, message, throwable);
			return;
		}
		if ( level > _logLevel ) return;
		if ( throwable != null )
		{
			ByteArrayOutputStream b = new ByteArrayOutputStream();
			throwable.printStackTrace(new PrintStream(b, true));
			message += ": " + new String(b.toByteArray());
		}
		System.err.println(shortenName(source) + ": " + message);
	}

	public static void log(Object source, int level,
			String message)
	{
		log(source, level, message, null);
	}
	
	public static void logThrowable(Object source, int level,
		String message, Throwable throwable)
	{
		log(source, level, message, throwable);
	}
	
	public static void hexlog(Object source, int level,
		String message, byte[] raw)
	{
		if ( logWrapper != null )
		{
			logWrapper.hexlog(source, level, message, raw);
			return;
		}
		hexlog(source, level, message, raw, 0, raw.length);
	}

	public static void hexlog(Object source, int level,
		String message, byte[] raw, int offset, int length)
	{
		if ( logWrapper != null )
		{
			logWrapper.hexlog(source, level, message, raw, offset, length);
			return;
		}
		if ( level > _logLevel ) return;
		log(source, level, message
			+ Conversions.bytesToHexString(raw, offset, length), null);
	}
	
	public static String shortenName(Object source)
	{
		if ( source == null ) return "";
		String classname = source.getClass().getName();
		int lastDot = classname.lastIndexOf((int)'.');
		if ( lastDot != -1 )
			classname = classname.substring(lastDot + 1);
		return classname + "@" + source.hashCode();
	}
	
	public static void setDelegate(LoggerDelegate myLogWrapper)
	{
		logWrapper = myLogWrapper;
	}
	
	public static LoggerDelegate getDelegate()
	{
		return logWrapper;
	}
}