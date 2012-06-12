package com.hush.hee.axbridge;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.Set;
import java.util.Vector;

import com.hush.hee.HushEncryptionEngineCore;
import com.hush.hee.KeyStoreException;
import com.hush.hee.NoEncryptionMethodException;
import com.hush.pgp.DataFormatException;
import com.hush.pgp.InvalidSignatureException;
import com.hush.pgp.MissingSelfSignatureException;
import com.hush.pgp.PgpConstants;
import com.hush.pgp.io.IntegrityCheckFailureException;
import com.hush.pgp.io.NoSessionKeyException;
import com.hush.util.Conversions;
import com.hush.util.UnrecoverableKeyException;

public class HushEncryptionEngineImpl implements PgpConstants
{
	private String characterEncoding = UTF8;

	private HushEncryptionEngineCore delegate = new HushEncryptionEngineCore();

	private byte[] toBytes(String string)
	{
		return Conversions.stringToByteArray(string, characterEncoding);
	}

	private String toString(byte[] bytes)
	{
		return Conversions.byteArrayToString(bytes, characterEncoding);
	}

	private HushEncryptionEngineCore getDelegate()
	{
		return delegate;
	}

	public void setCharacterEncoding(String characterEncoding)
	{
		this.characterEncoding = characterEncoding;
	}

	public String getCharacterEncoding()
	{
		return characterEncoding;
	}

	public void authenticate(String userAlias, String passphrase)
			throws UnrecoverableKeyException, IOException, KeyStoreException
	{
		getDelegate().authenticate(userAlias, toBytes(passphrase));
	}

	public void checkCanEncrypt(SecureMessage secureMessage,
			CanEncryptResult result) throws KeyStoreException, IOException,
			InvalidSignatureException, MissingSelfSignatureException
	{
		CanEncryptResult interimResult = new CanEncryptResult(getDelegate().checkCanEncrypt(
				secureMessage.getDelegate()));
		result.setAliasesWithEncryptionMethod(interimResult
				.getAliasesWithEncryptionMethod());
		result.setAliasesWithNoEncryptionMethod(interimResult
				.getAliasesWithNoEncryptionMethod());
		result.setDeniedAliases(interimResult.getDeniedAliases());
	}

	public void decryptFileToFile(String sourceFilePath, String targetFilePath)
			throws DataFormatException, FileNotFoundException,
			NoSessionKeyException, IntegrityCheckFailureException, IOException
	{
		getDelegate().decryptFile(sourceFilePath, null, null, targetFilePath);
	}
	
	public void decryptFile(String sourceFilePath)
			throws DataFormatException, FileNotFoundException,
			NoSessionKeyException, IntegrityCheckFailureException, IOException
	{
		getDelegate().decryptFile(sourceFilePath, null, null);
	}

	public void decryptText(String text, StringHolder result)
			throws DataFormatException, NoSessionKeyException,
			IntegrityCheckFailureException, UnsupportedEncodingException,
			IOException
	{
		String decrypted = getDelegate().decryptText(toBytes(text), null);
		result.setString(decrypted);
	}

	public void encrypt(SecureMessage secureMessage)
			throws NoEncryptionMethodException, KeyStoreException, IOException
	{
		getDelegate().encrypt(secureMessage.getDelegate());
	}

	public void encryptFileToFile(String sourceFilePath, String targetFilePath,
			SecureMessage secureMessage) throws NoEncryptionMethodException,
			KeyStoreException, IOException
	{
		_encryptAndSignFileToFile(sourceFilePath, targetFilePath, secureMessage, false);
	}
	
	public void encryptAndSignFileToFile(String sourceFilePath, String targetFilePath,
			SecureMessage secureMessage) throws NoEncryptionMethodException,
			KeyStoreException, IOException
	{
		_encryptAndSignFileToFile(sourceFilePath, targetFilePath, secureMessage, true);
	}
	
	public void isPassphraseExpired(BooleanHolder result)
		throws KeyStoreException
	{
		result.setBoolean(getDelegate().isPassphraseExpired());
	}
	
	private void _encryptAndSignFileToFile(String sourceFilePath, String targetFilePath,
			SecureMessage secureMessage, boolean sign) throws NoEncryptionMethodException,
			KeyStoreException, IOException
	{
		FileInputStream in = null;
		FileOutputStream out = null;

		try
		{
			in = new FileInputStream(sourceFilePath);
			out = new FileOutputStream(targetFilePath);
			secureMessage.getDelegate().setInputStream(in);
			secureMessage.getDelegate().setOutputStream(out);
			if ( sign )
			{
				getDelegate().encryptAndSign(secureMessage.getDelegate());
			}
			else
			{
				getDelegate().encrypt(secureMessage.getDelegate());
			}
		}
		finally
		{
			try
			{
				if (in != null)
					in.close();
			}
			catch (Exception ee)
			{
			}
			try
			{
				if (out != null)
					out.close();
			}
			catch (Exception ee)
			{
			}
			secureMessage.getDelegate().setInputStream(null);
			secureMessage.getDelegate().setOutputStream(null);
		}
	}

	public void getAdditionalDecryptionKeyAcceptanceList(String domain,
			Set additionalDecryptionKeyAcceptanceList) throws KeyStoreException
	{
		// Return empty, as this is done within the public key lookup now.
		additionalDecryptionKeyAcceptanceList.clear();
	}

	public void getAdditionalDecryptionKeyAliases(String domain,
			Set additionalDecryptionKeyAliases) throws KeyStoreException
	{
		// Return empty, as this is done within the public key lookup now.
		additionalDecryptionKeyAliases.clear();
	}

	public void setParameter(String key, String value)
	{
		getDelegate().setParameter(key, value);
	}

	public void signFile(String filePath, StringHolder signature)
			throws IOException, KeyStoreException
	{
		signature.setString(toString(getDelegate().signFile(filePath)));
	}

	public void signText(String text, boolean detached, StringHolder signature)
	{
		signature.setString(getDelegate().signText(text,
				getCharacterEncoding(), detached));
	}

	public int verifyCleartextSignedMessage(String signer,
			String signedMessage, Set validSigners, Set invalidSigners,
			StringHolder content) throws DataFormatException, IOException,
			KeyStoreException
	{
		validSigners.clear();
		invalidSigners.clear();
		Vector validSignersVector = new Vector();
		Vector invalidSignersVector = new Vector();
		String[] contentArray = new String[1];
		int result = getDelegate().verifyCleartextSignedMessage(signer,
				signedMessage, validSignersVector, invalidSignersVector,
				contentArray);
		validSigners.addAll(validSignersVector);
		invalidSigners.addAll(invalidSignersVector);
		content.setString(contentArray[0]);
		return result;
	}

	public int verifyFile(String signer, String filePath, String signature,
			Set validSigners, Set invalidSigners) throws DataFormatException,
			IOException, KeyStoreException
	{
		validSigners.clear();
		invalidSigners.clear();
		Vector validSignersVector = new Vector();
		Vector invalidSignersVector = new Vector();
		int result = getDelegate().verifyFile(signer, filePath, signature,
				validSignersVector, invalidSignersVector);
		validSigners.addAll(validSignersVector);
		invalidSigners.addAll(invalidSignersVector);
		return result;
	}
}
