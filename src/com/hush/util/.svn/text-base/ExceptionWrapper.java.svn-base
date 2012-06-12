package com.hush.util;

import java.io.IOException;

public class ExceptionWrapper
{
	public static RuntimeException wrapInRuntimeException(String message, Exception exception)
	{
		Logger.logThrowable(null, Logger.ERROR, message, exception);
		throw new RuntimeException(message, exception);
	}

	public static IllegalArgumentException wrapInIllegalArgumentException(
			String message, Exception exception)
	{
		Logger.logThrowable(null, Logger.ERROR, message, exception);
		return new IllegalArgumentException(message, exception);
	}
	
	public static IOException wrapInIOException(
			String message, Exception exception)
	{
		Logger.logThrowable(null, Logger.ERROR, message, exception);
		return new IOException(message, exception);
	}
}
