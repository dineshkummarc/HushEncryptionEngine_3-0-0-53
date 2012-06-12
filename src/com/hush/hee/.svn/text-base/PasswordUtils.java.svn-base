package com.hush.hee;

import java.io.UnsupportedEncodingException;
import java.security.SecureRandom;

import org.bouncycastle.crypto.digests.SHA256Digest;

import com.hush.hee.util.StringReplace;
import com.hush.util.Conversions;

public class PasswordUtils
{
	public static String generatePasswordHash(String encryptionKey)
	{
		SHA256Digest sha = new SHA256Digest();
		byte[] answerHashBytes = new byte[sha.getDigestSize()];
		byte[] input = encryptionKey.getBytes();
		sha.update(input, 0, input.length);
		sha.doFinal(answerHashBytes, 0);
		sha.reset();
		return Conversions.bytesToHexString(answerHashBytes).toLowerCase();
	}
	
	public static String generateEncryptionKey(String salt, String password)
	{
		SHA256Digest sha = new SHA256Digest();
		byte[] encryptionKey = new byte[sha.getDigestSize()];
		byte[] input = (salt + ":" + canonicalizePassword(password)).getBytes();
		sha.update(input, 0, input.length);
		sha.doFinal(encryptionKey, 0);
		sha.reset();
	
		return Conversions.bytesToHexString(encryptionKey).toLowerCase();
	}
	
	public static String canonicalizePassword(String password)
	{
		if (password == null)
			password = "";
		byte[] bytes;
		try
		{
			bytes = password.getBytes("UTF-8");
		}
		catch (UnsupportedEncodingException e)
		{
			bytes = password.getBytes();
		}
		String canonicalizedAnswer = new String(bytes).toLowerCase();
		canonicalizedAnswer = StringReplace.replace(canonicalizedAnswer, "[", "");
		canonicalizedAnswer = StringReplace.replace(canonicalizedAnswer, ",", "");
		canonicalizedAnswer = StringReplace.replace(canonicalizedAnswer, ".", "");
		canonicalizedAnswer = StringReplace.replace(canonicalizedAnswer, "-", "");
		canonicalizedAnswer = StringReplace.replace(canonicalizedAnswer, " ", "");
		canonicalizedAnswer = StringReplace.replace(canonicalizedAnswer, "]", "");
		return canonicalizedAnswer;
	}

	public static String generateAnswerSalt()
	{
		byte[] randBytes = new byte[16];
		new SecureRandom().nextBytes(randBytes);
		return
			Conversions.bytesToHexString(randBytes).toLowerCase();
	}

}
