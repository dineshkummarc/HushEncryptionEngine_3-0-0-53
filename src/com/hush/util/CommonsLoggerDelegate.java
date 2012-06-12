package com.hush.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.hush.hee.HushEncryptionEngineCore;

public class CommonsLoggerDelegate implements LoggerDelegate
{
	private Log log;
	
	public CommonsLoggerDelegate(Log log)
	{
		this.log = log;
	}

	public static void install()
	{
		install(null);
	}
	
	public static void install(Log log)
	{
		LoggerDelegate delegate = Logger.getDelegate();
		if (delegate == null
				|| !CommonsLoggerDelegate.class.equals(delegate
						.getClass()))
		{
			if ( log == null )
				log = LogFactory.getLog(HushEncryptionEngineCore.class);
			Logger.setDelegate(new CommonsLoggerDelegate(log));
			Logger.log(null, Logger.INFO, "Apache Commons Logging initialized");
		}
	}
	
	public void log(Object sourceObj, int level, String message,
			Throwable t)
	{
		String source = Logger.shortenName(sourceObj);
		switch (level)
		{
		case Logger.ERROR:
		case Logger.NONE:
			log.error(source + ": " + message, t);
			break;
		case Logger.WARNING:
			log.warn(source + ": " + message, t);
			break;
		case Logger.INFO:
			log.info(source + ": " + message, t);
			break;
		case Logger.DEBUG:
			log.debug(source + ": " + message, t);
			break;
		case Logger.VERBOSE:
			log.trace(source + ": " + message, t);
			break;
		default:
			log.error(source + ": " + message, t);
		}
	}

	public void hexlog(Object source, int level, String message, byte[] raw)
	{
		hexlog(source, level, message, raw, 0, raw.length);
	}

	public void hexlog(Object source, int level, String message, byte[] raw, int offset, int length)
	{
		switch (level)
		{
		case Logger.ERROR:
		case Logger.NONE:
			if ( ! log.isErrorEnabled() )
			{
				return;
			}
			break;
		case Logger.WARNING:
			if ( ! log.isWarnEnabled() )
			{
				return;
			}
			break;
		case Logger.INFO:
			if ( ! log.isInfoEnabled() )
			{
				return;
			}
			break;
		case Logger.DEBUG:
			if ( ! log.isDebugEnabled() )
			{
				return;
			}
			break;
		default:
			if ( ! log.isErrorEnabled() )
			{
				return;
			}
		}
		log(source, level, message
				+ Conversions.bytesToHexString(raw, offset, length), null);
	}
}
