package com.hush.hee.axbridge;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.util.Set;
import java.util.TreeSet;

import com.hush.hee.HushEncryptionEngineCore;
import com.hush.hee.KeyStoreException;
import com.hush.hee.NeedsAuthenticationException;
import com.hush.hee.net.UnableToConnectToKeyserverException;
import com.hush.pgp.DataFormatException;
import com.hush.pgp.PgpConstants;
import com.hush.util.UnrecoverableKeyException;

public abstract class HushEncryptionEngineBase implements
		HushEncryptionEngineInterface, PgpConstants
{	
	private boolean inited = false;
	
	private String lastErrorTrace = null;
	
	private String lastErrorMessage = null;
	
	private HushEncryptionEngineImpl delegate = new HushEncryptionEngineImpl();
	
	protected HushEncryptionEngineImpl getDelegate()
	{
		return delegate;
	}
	
	protected int processThrowable(Throwable t)
	{
		storeError(t);
		if (t instanceof NeedsAuthenticationException )
			return ERROR_AUTHENTICATION_REQUIRED;
		if (t instanceof UnableToConnectToKeyserverException )
			return ERROR_COULD_NOT_CONNECT_TO_KEYSERVER;
		if (t instanceof KeyStoreException)
			return ERROR_KEYSTORE_EXCEPTION;
		if (t instanceof DataFormatException)
			return ERROR_BAD_FORMAT;
		if (t instanceof IOException)
			return ERROR_IO_EXCEPTION;
		if (t instanceof UnrecoverableKeyException)
			return ERROR_BAD_PASSPHRASE;
		return ERROR_EXCEPTION;
	}

	protected void storeError(Throwable t)
	{
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		PrintWriter pw = new PrintWriter(new OutputStreamWriter(out));
		t.printStackTrace(pw);
		pw.flush();
		t.printStackTrace();
		lastErrorMessage = t.getMessage();
		lastErrorTrace = new String(out.toByteArray());
	}
	
	public String getLastErrorMessage()
	{
		return lastErrorMessage;
	}
	
	public String getLastErrorTrace()
	{
		return lastErrorTrace;
	}
	
	public void setCharacterEncoding(String characterEncoding)
	{
		getDelegate().setCharacterEncoding(characterEncoding);
	}
	
	public String getCharacterEncoding()
	{
		return getDelegate().getCharacterEncoding();
	}
	
	public SecureMessage createSecureMessage()
	{
		return new SecureMessage();
	}
	
	public CanEncryptResult createCanEncryptResult()
	{
		return new CanEncryptResult(new com.hush.hee.CanEncryptResult(null, null, null));
	}
	
	public QuestionAndAnswer createQuestionAndAnswer()
	{
		return new QuestionAndAnswer(new com.hush.hee.QuestionAndAnswer());
	}
	
	public StringHolder createStringHolder()
	{
		return new StringHolder();
	}
	
	public BooleanHolder createBooleanHolder()
	{
		return new BooleanHolder();
	}
	
	public Set createSet()
	{
		return new TreeSet();
	}
	
	public String getVersionAsString()
	{
		return HushEncryptionEngineCore.getVersionAsString();
	}
	
	public long getVersionAsLong()
	{
		return HushEncryptionEngineCore.getVersionAsLong();
	}
}
