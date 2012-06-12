package com.hush.test.pgp;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;

public class TestDataLoader
{
	private Collection signatureTestData;
	private String signatureDirectory = "testdata/signatures/";
	private String dummyFile = "testdata/Water_lilies.jpg";
	
	public class SignatureTestData
	{
		private String signature;
		private File data;
		private String publicKey;

		public void setData(File data)
		{
			this.data = data;
		}
		public File getData()
		{
			return data;
		}
		public String getDataAsString()
		{
			try
			{
				return fileAsString(getData());
			}
			catch (IOException e)
			{
				throw new RuntimeException(e);
			}	
		}
		public String getPublicKey()
		{
			return publicKey;
		}
		public void setPublicKey(String publicKey)
		{
			this.publicKey = publicKey;
		}
		public String getSignature()
		{
			return signature;
		}
		public void setSignature(String signature)
		{
			this.signature = signature;
		}
	}
	
	public TestDataLoader() throws IOException
	{
		signatureTestData = new ArrayList();
		int x=0;
		while(true)
		{
			SignatureTestData sigData = new SignatureTestData();
			File sigFile = new File(signatureDirectory + x + ".sig");
			if ( ! sigFile.isFile() )
			{
				break;
			}

			sigData.setPublicKey(fileAsString(new File(signatureDirectory + x + ".key")));
			sigData.setData(new File(signatureDirectory + x + ".data"));
			sigData.setSignature(fileAsString(sigFile));
			signatureTestData.add(sigData);
			x++;
		}
	}
	public Collection getSignatureTestData()
	{
		return signatureTestData;
	}
	
	public static String fileAsString(File f) throws IOException
	{
		FileReader fr = new FileReader(f);
		StringBuffer s = new StringBuffer();
		char[] buffer = new char[2048];
		for(int x=fr.read(buffer);x!=-1;x=fr.read(buffer))
		{
			s.append(buffer, 0, x);
		}
		return s.toString();
	}
	
	public static byte[] fileAsByteArray(File f) throws IOException
	{
		FileInputStream fr = new FileInputStream(f);
		ByteArrayOutputStream s = new ByteArrayOutputStream();
		byte[] buffer = new byte[2048];
		for(int x=fr.read(buffer);x!=-1;x=fr.read(buffer))
		{
			s.write(buffer, 0, x);
		}
		return s.toByteArray();
	}
	
	public String getDummyFile()
	{
		return dummyFile;
	}
}
