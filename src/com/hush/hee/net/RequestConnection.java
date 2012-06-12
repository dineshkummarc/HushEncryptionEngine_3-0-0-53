/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.hee.net;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.MalformedURLException;

import com.hush.hee.BadRequestException;
import com.hush.hee.DeniedException;
import com.hush.hee.KeyStoreException;
import com.hush.net.HttpRequest;
import com.hush.pgp.PgpConstants;
import com.hush.util.Conversions;
import com.hush.util.ExceptionWrapper;

public class RequestConnection implements RequestConstants
{
	private BufferedReader in;

	protected HttpRequest httpRequest;

	private Request request;

	private OutputStream requestBuffer;

	public RequestConnection(String server, Request request)
	{
		try
		{
			httpRequest = createHttpRequest("https://" + server);
			this.request = request;
		}
		catch (MalformedURLException e)
		{
			ExceptionWrapper.wrapInIllegalArgumentException(
					"Invalid server, or no HTTPS support: " + server, e);
		}
	}

	/**
	 * Executes each Request object's <code>sendRequest</code> method in order,
	 * and then executes each Request object's <code>processReply</code> method
	 * in the same order.  Each Request object can return an Object, containing
	 * any information returned by the server; these responses are stored in
	 * single Vector, which is returned at the end of the <code>execute</code>
	 * method.
	 * 
	 * @return an Vector of Objects created by the Request's execution.
	 * @exception ProtocolException thrown when the protocol is violated.
	 */
	public void execute() throws KeyStoreException, IOException
	{
		String line;

		httpRequest.open();

		requestBuffer = getOutputStream();

		//urlConnection.getOutputStream();
		// add xml header
		write(XML_HEADER);

		// add request header
		write(REQUEST_BLOCK_START);

		// Set the connection for the Request.
		request.setConnection(RequestConnection.this);

		// Send the request.
		// This causes the request object to write XML to
		// requestBuffer.
		request.sendRequest();

		// add request close
		write(REQUEST_BLOCK_START_END);

		// We have to close the stream here and not rely on the underlying
		// HTTPRequest to do so.  That's because the stream may not be the
		// stream that is a member of HTTPRequest, it may be a wrapper on it
		// that also needs to be closed.  This is the case for signed requests.
		requestBuffer.close();

		httpRequest.connect();

		if (httpRequest.getStatusCode() != HttpRequest.HTTP_OK)
			throw new KeyStoreException(
				"Unexpected HTTP status code: " + httpRequest.getStatusCode());

		in =
			new BufferedReader(
				new InputStreamReader(httpRequest.getInputStream()));

		// Read the first tag, which should be xml header.
		line = readLine();

		if ( line == null )
			throw new KeyStoreException("null first line from keyserver");
		
		if (line.length() < 6 || !line.substring(0,6).equalsIgnoreCase(XML_HEADER.substring(0,6)))
			throw new KeyStoreException("Expecting: " + XML_HEADER.substring(0,6));

		line = readLine();
		Tokeniser toplevelElement = new Tokeniser(line);

		if (!RESPONSE_BLOCK.equalsIgnoreCase(toplevelElement.name))
		{
			// Either error or something unexpected
			if (!ERROR.equalsIgnoreCase(toplevelElement.name))
			{
				throw new KeyStoreException(
					"Expecting " + RESPONSE_BLOCK + " or " + ERROR);
			}
			else
			{
				String status = (String)toplevelElement.htAttr.get(STATUS);
				
				line = readLine();
				Tokeniser t = new Tokeniser(line);

				String message;
				
				if ("errorMessage".equalsIgnoreCase(t.name))
				{
					message = CDATAReader.process(this);
				}
				else
				{
					message = "Expected errorMessage element in error";
				}
				
				if (STATUS_DENIED.equals(status))
					throw new DeniedException(message);
				if (STATUS_BAD_REQUEST.equals(status))
					throw new BadRequestException(message);
				throw new KeyStoreException(message);
			}
		}
		else
		{
			request.processResponse();

			line = readLine();

			if (!line.equalsIgnoreCase(RESPONSE_BLOCK_FINISH))
				throw new KeyStoreException(
					"Expecting " + RESPONSE_BLOCK_FINISH);
		}

		in.close();

	}

	public OutputStream getOutputStream() throws IOException
	{
		return httpRequest.getOutputStream();
	}

	public int read() throws IOException
	{
		int x = in.read();
		//System.err.print(( x > 0 ? (char) x : x ));
		return x;
	}

	public void read(char[] c) throws IOException
	{
		in.read(c);
		//System.err.print(new String(c));
	}

	public String readLine() throws IOException
	{
		String line = in.readLine();
		//System.err.println("READ LINE: " + line);
		return line == null ? null : line.trim();
	}

	public void write(byte[] b)
	{
		try
		{
			requestBuffer.write(b);
		}
		catch (IOException e)
		{
			throw ExceptionWrapper.wrapInRuntimeException("Should never happen", e);
		}
	}

	public void write(String s)
	{
		//System.err.println("WRITE: " + s);
		try
		{
			requestBuffer.write(Conversions.stringToByteArray(s,
					PgpConstants.UTF8));
		}
		catch (IOException e)
		{
			throw ExceptionWrapper.wrapInRuntimeException("Should never happen", e);
		}
	}

	public void mark(int mark) throws IOException
	{
		in.mark(mark);
	}

	public void reset() throws IOException
	{
		in.reset();
	}
	
	protected HttpRequest createHttpRequest(String url) throws MalformedURLException
	{
		return new HttpRequest(url, true, XML_CONTENT_TYPE);	
	}
}