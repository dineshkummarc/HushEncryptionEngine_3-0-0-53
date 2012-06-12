/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.net;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.net.URLStreamHandlerFactory;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Properties;
import java.util.Random;

import com.hush.applet.security.Badge;
import com.hush.applet.security.Strategy;

/**
 * Makes a http/https network connection for the requested url and provides the
 * client of this class an InputStream to the Socket.
 */
public class HttpRequest
{
	/**
	 * The HTTP 'ok' response header.
	 */
	public static final int HTTP_OK = 200;

	/**
	 * The HTTP 'Content-type' request header.
	 */
	public static final String HTTP_CONTENT_TYPE_HEADER = "Content-type";

	/**
	 * The HTTP 'Character-encoding' request header.
	 */
	public static final String HTTP_CHARACTER_ENCODING_HEADER =
		"Character-encoding";

	/**
	 * The standard form type.
	 */
	public static final String X_WWW_FORM_URL_ENCODED =
		"application/x-www-form-urlencoded";

	/**
	 * The multipart form type.
	 */
	public static final String MULTIPART_FORM_DATA = "multipart/form-data";

	static {
		try
		{
			URL testURL = new URL("https://192.168.0.1");
		}
		catch (MalformedURLException mE)
		{
			try
			{
				Class msFactory =
					Class.forName(
						"com.ms.net.wininet.WininetStreamHandlerFactory");
				URL.setURLStreamHandlerFactory(
					(URLStreamHandlerFactory) msFactory.newInstance());
				System.err.println(
					"Using stream handler from com.ms.net.wininet");
			}
			catch (Throwable t)
			{
				try
				{
					// Add protocol handler package to system properties
					Properties properties = System.getProperties();
					properties.put(
						"java.protocol.handler.pkgs",
						"com.sun.net.ssl.internal.www.protocol");
					System.setProperties(properties);

					// Add Sun's SSL provider.
					Class securityClass =
						Class.forName("java.security.Security");
					java.lang.reflect.Method addProviderMethod =
						securityClass.getMethod(
							"addProvider",
							new Class[] {
								 Class.forName("java.security.Provider")});
					Class sslProviderClass =
						Class.forName("com.sun.net.ssl.internal.ssl.Provider");
					addProviderMethod.invoke(null /* static method */
					, new Object[] { sslProviderClass.newInstance()});
					System.err.println("Using JSSE");
				}
				catch (Throwable t2)
				{
					t2.printStackTrace();
					System.err.println(
						"Neither Microsoft nor JSSE SSL support available.");
					System.err.println(
						"In fact, there is no HTTPS support at all.");
					System.err.println(
						"Expect exceptions on all connection attempts!");
				}
			}
		}
	}

	/**
	 * The URLConnection connected to the URL.
	 */
	private URLConnection urlConnection;

	/**
	 * The http content length of the response.
	 */
	private int contentLength = 0;

	/**
	 * The HTTP status code
	 */
	private int statusCode;

	/**
	 * The HTTP status reason
	 */
	private String statusReason = null;

	/**
	 * The url to be retrieved.
	 */
	private URL url;

	/**
	 * The outgoing content type for POST request.
	 */
	private String outgoingContentType;

	/**
	 * Indicates if this is a HTTP GET or HTTP POST.
	 */
	private boolean post = false;

	/**
	 * Needed for exceptions in execute.
	 */
	private IOException ioException;

	/**
	 * The form to send to the URL.
	 */
	private Hashtable form;

	/**
	 * The character encoding for the form.
	 */
	private String characterEncoding = "UTF8";

	/**
	 * The boundary for "form/data" POST requests.
	 */
	private String boundary = "hush_boundary_";

	private InputStream inputStream;

	private OutputStream outputStream;

	protected HttpRequest()
	{
	}

	/**
	 * Creates a new connection to a URL.
	 * 
	 * @param url the URL to connect
	 */
	public HttpRequest(String url) throws MalformedURLException
	{
		this.url = new URL(url);
	}

	/**
	 * Creates a new connection to a URL
	 * 
	 * @param url the URL to connect
	 * @param post set to true to to an HTTP post
	 * @param contentType set the content type for an http post
	 */
	public HttpRequest(String url, boolean post, String contentType)
		throws MalformedURLException
	{
		this.url = new URL(url);
		this.post = post;

		if (MULTIPART_FORM_DATA.equals(contentType))
		{
			Random rnd = new Random();

			int min = 65;

			for (int i = 0; i < 32; i++)
			{
				if (rnd.nextDouble() < .5)
				{
					min = 65;
				}
				else
				{
					min = 97;
				}

				boundary += (char) (int) (rnd.nextDouble() * 26 + min);
			}

			outgoingContentType = contentType + "; boundary=" + boundary;
		}
		else
			outgoingContentType = contentType;
	}

	public int contentLength()
	{
		return contentLength;
	}

	/**
	 * Returns the url
	 */
	public URL getURL()
	{
		return url;
	}

	/**
	 * Parses the status code from the connection stream.
	 */
	public void parseStatusCode(URLConnection urlConnection)
	{
		String headers;

		try
		{
			// First, try to get the HTTP/1.1 response header Mac IE and Windows IE style
			headers = urlConnection.getHeaderField(0);

			// If this fails, try this way that works on Windows IE.
			// It'll crash Mac IE, but Mac IE would've worked on the previous try.
			// This one is probably unnecessary.  I'm pretty sure that anything that works
			// with this would work with the one just above it.
			// 
			// There's an exception handler because it throws a NullPointerException in Opera
			try
			{
				if (headers == null)
				{
					headers = urlConnection.getHeaderField(null);
				}
			}
			catch (Throwable t)
			{
			}

			// If using Netscape 4.x, must use this way.
			if (headers == null)
			{
				headers = urlConnection.getHeaderFieldKey(0);
			}

			// Sun VM 1.3 only has content type and content length headers available, both based
			// on a "best guess algorithm" (see http://java.sun.com/products/plugin/1.3/docs/https.html).
			// All we can do is assume HTTP_OK if no other HTTP response codes are found in the
			// first header - see first option below
			// Test for various HTTP response codes.
			if (headers == null)
			{
				// Sun VM - see note above.
				statusCode = HTTP_OK;
			}

			int spaceIndex = headers.indexOf(" ");
			if (spaceIndex != -1 && spaceIndex != headers.length() - 1)
			{
				String statusString =
					headers.substring(headers.indexOf(" ") + 1);
				spaceIndex = statusString.indexOf(" ");
				if (spaceIndex != -1
					&& spaceIndex != statusString.length() - 1)
				{
					try
					{
						statusCode =
							Integer.parseInt(
								statusString.substring(0, spaceIndex));
						statusReason = statusString.substring(spaceIndex + 1);
					}
					catch (NumberFormatException n)
					{
					}
				}
			}
			else
			{
				statusCode = HTTP_OK;
			}
		}
		catch (Throwable t)
		{
			statusCode = HTTP_OK;
		}
	}

	public int getStatusCode()
	{
		return statusCode;
	}

	public String getStatusReason()
	{
		return statusReason;
	}

	/**
	 * Attempts to connect to the requested url, checking for the required Java 
	 * permissions.
	 *
	 * @throws IOException if there is a failure to connect
	 */
	public void open() throws IOException
	{
		ioException = null;

		// create a strategy for your specific browser
		Strategy strategy = Strategy.createStrategy();

		// create a badge to perform the tasks requiring privileges
		strategy.handle(new Badge()
		{
			public void invoke(Strategy strat)
			{
				try
				{
					// Initializes the connection to the server.
					urlConnection = url.openConnection();
					urlConnection.setAllowUserInteraction(true);
					urlConnection.setUseCaches(false);
					urlConnection.setDoOutput(post);
					urlConnection.setDoInput(true);

					if (post)
					{
						// Set the content-type for the POST-ed body
						urlConnection.setRequestProperty(
							HTTP_CONTENT_TYPE_HEADER,
							outgoingContentType);

						urlConnection.setRequestProperty(
							HTTP_CHARACTER_ENCODING_HEADER,
							characterEncoding);

						outputStream = urlConnection.getOutputStream();
					}

				}
				catch (IOException e)
				{
					ioException = e;
				}
			}
		});

		if (ioException != null)
		{
			throw ioException;
		}
	}

	/**
	 * Connects to the URL, and writes any information.
	 */
	public void connect() throws IOException
	{
		if (post && form != null)
		{
			Enumeration e = form.keys();
			String key;

			if (X_WWW_FORM_URL_ENCODED.equals(outgoingContentType))
			{

				while (e.hasMoreElements())
				{
					key = (String) e.nextElement();
					getOutputStream().write(
						URLEncoder.encode(key).getBytes(characterEncoding));
					getOutputStream().write("=".getBytes(characterEncoding));
					getOutputStream().write(
						URLEncoder.encode((String) form.get(key)).getBytes(
							characterEncoding));
					if (e.hasMoreElements())
						getOutputStream().write(
							"&".getBytes(characterEncoding));
				}
			}
			else if (
				MULTIPART_FORM_DATA.equals(
					outgoingContentType.substring(
						0,
						MULTIPART_FORM_DATA.length())))
			{
				while (e.hasMoreElements())
				{
					key = (String) e.nextElement();
					getOutputStream().write("--".getBytes(characterEncoding));
					getOutputStream().write(
						boundary.getBytes(characterEncoding));
					getOutputStream().write("\r\n".getBytes(characterEncoding));
					getOutputStream().write(
						"Content-Disposition: form-data; name=\"".getBytes(
							characterEncoding));
					getOutputStream().write(key.getBytes(characterEncoding));
					getOutputStream().write(
						"\"\r\n\r\n".getBytes(characterEncoding));
					getOutputStream().write(
						((String) form.get(key)).getBytes(characterEncoding));
					getOutputStream().write("\r\n".getBytes(characterEncoding));
				}
				getOutputStream().write("--".getBytes(characterEncoding));
				getOutputStream().write(boundary.getBytes(characterEncoding));
				getOutputStream().write("\r\n".getBytes(characterEncoding));
			}
		}

		// We have to be careful here, because in the past it has caused
		// problems because the output stream was already closed by the
		// calling code.  This specifically raises an exception in Opera.
		// So we will try to close the stream, but catch and ignore any
		// resulting exception.
		if (post)
		{
			try
			{
				getOutputStream().close();
			}
			catch (Exception e)
			{
				// Don't raise an error here.  It won't cause
				// any problem for this to happen.
			}
		}

		ioException = null;

		// create a strategy for your specific browser
		Strategy strategy = Strategy.createStrategy();

		// create a badge to perform the tasks requiring privileges
		strategy.handle(new Badge()
		{
			public void invoke(Strategy strat)
			{
				try
				{
					urlConnection.connect();

					// Parse the response status code.
					parseStatusCode(urlConnection);

					if (statusCode >= 200 && statusCode < 300)
						inputStream = urlConnection.getInputStream();

					contentLength = urlConnection.getContentLength();
				}
				catch (IOException e)
				{
					ioException = e;
				}
			}
		});

		if (ioException != null)
		{
			throw ioException;
		}
	}

	/**
	 * Gets the output stream to the URL.
	 *
	 */
	public OutputStream getOutputStream() throws IOException
	{
		return outputStream;
	}

	/**
	 * Gets the input stream from the URL.
	 *
	 */
	public InputStream getInputStream() throws IOException
	{
		return inputStream;
	}

	/**
	 * Set the form to POST to the URL.
	 */
	public void setForm(Hashtable form)
	{
		if (form == null || form.size() == 0)
		{
			this.form = null;
			return;
		}
		if (!post)
			throw new IllegalStateException("Can't specify a form for an HTTP GET request");
		this.form = form;
	}

	/**
	 * Returns the boundary for multipart/form-data requests.
	 */
	public String getBoundary()
	{
		return boundary;
	}
}