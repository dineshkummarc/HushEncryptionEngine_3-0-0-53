package com.hush.util;


/**
 * Provided to allow for overriding the simple System.err logging in
 * Logger.  There is a reason this is a separate interface!!!!!!!
 * Self-referencing classes are bad in webapps, they cause memory leaks. -sbs
 * 
 */
public interface LoggerDelegate
{
	public void log(Object source, int level,
			String message, Throwable throwable);
	
	public void hexlog(Object source, int level,
			String message, byte[] raw);
	
	public void hexlog(Object source, int level,
			String message, byte[] raw, int offset, int length);
}
