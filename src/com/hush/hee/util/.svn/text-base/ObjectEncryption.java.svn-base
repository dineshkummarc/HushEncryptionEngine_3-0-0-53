package com.hush.hee.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;

import com.hush.util.ExceptionWrapper;

public class ObjectEncryption
{
	public static Object passwordDecryptObject(
			byte[] cipherText, byte[] password)
			throws IOException, ClassNotFoundException
	{
		byte[] plaintext = process(false, password, cipherText);
		ObjectInputStream myObjectReader = new ObjectInputStream(
				new ByteArrayInputStream(plaintext));
		return myObjectReader.readObject();
	}

	public static byte[] passwordEncryptObject(Object object, byte[] password,
			SecureRandom random) throws IOException
	{
		ByteArrayOutputStream objectByteStream = new ByteArrayOutputStream();
		ObjectOutputStream objectWriter = new ObjectOutputStream(objectByteStream);
		objectWriter.writeObject(object);
		objectWriter.close();
		byte[] objectBytes = objectByteStream.toByteArray();
		return process(true, password, objectBytes);
	}
	
	private static byte[] process(boolean encrypt, byte[] password, byte[] input)
			throws IOException
	{
		AESFastEngine engine = new AESFastEngine();
		PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(
				new CBCBlockCipher(engine));
		cipher.init(encrypt, new KeyParameter(password));
		byte[] output = new byte[cipher.getOutputSize(input.length)];

		int outputLen = cipher.processBytes(input, 0, input.length, output, 0);
		try
		{
			cipher.doFinal(output, outputLen);
		}
		catch (CryptoException ce)
		{
			throw ExceptionWrapper.wrapInIOException(
					"Object encryption or decryption failure", ce);
		}
		return output;
	}

}
