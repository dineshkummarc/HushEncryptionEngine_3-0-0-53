package com.hush.hee.axbridge;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

import java.util.Set;

import com.hush.hee.HushEncryptionEngineCore;

public interface HushEncryptionEngineInterface
{
	public static final int ERROR_NULL_ARGUMENT = -1;
	
	public static final int ERROR_BAD_FORMAT = -9;

	public static final int ERROR_BAD_PASSPHRASE = 1;

	public static final int ERROR_CERT_NOT_FOUND = -2;

	public static final int ERROR_EXCEPTION = -11;

	public static final int ERROR_FAILURE = -15;

	public static final int ERROR_IO_EXCEPTION = -16;

	public static final int ERROR_KEYSTORE_EXCEPTION = -7;
	
	public static final int ERROR_COULD_NOT_CONNECT_TO_KEYSERVER = -8;
	
	public static final int ERROR_AUTHENTICATION_REQUIRED = -9;

	public static final int ERROR_NO_ALIASES = -12;

	public static final int ERROR_NOT_INITIALIZED = -14;
	
	public static final int ERROR_SIGNATURE_INVALID = HushEncryptionEngineCore.SIGNATURE_INVALID;

	public static final int ERROR_SIGNATURE_VALID = HushEncryptionEngineCore.SIGNATURE_VALID;

	public static final int ERROR_SUCCESS = 0;
	
	@Retention(RetentionPolicy.RUNTIME)
	public @interface ArgumentName {
		String name();
	}
	
	@Retention(RetentionPolicy.RUNTIME)
	public @interface CanBeNull {
	}
	
	public int authenticate(@ArgumentName(name="userAlias") String userAlias, @ArgumentName(name="passphrase") String passphrase);
	
	public int checkCanEncrypt(@ArgumentName(name="secureMessage") SecureMessage secureMessage, @ArgumentName(name="result") CanEncryptResult result);
	
	public int decryptFileToFile(@ArgumentName(name="sourceFilePath") String sourceFilePath, @ArgumentName(name="targetFilePath") String targetFilePath);
	
	public int decryptFile(@ArgumentName(name="sourceFilePath") String sourceFilePath);
	
	public int decryptText(@ArgumentName(name="text") String text, @ArgumentName(name="result") StringHolder result);
	
	public int encryptFileToFile(@ArgumentName(name="sourceFilePath") String sourceFilePath, @ArgumentName(name="targetFilePath") String targetFilePath, @ArgumentName(name="secureMessage") SecureMessage secureMessage);
	
	public int encryptAndSignFileToFile(@ArgumentName(name="sourceFilePath") String sourceFilePath, @ArgumentName(name="targetFilePath") String targetFilePath, @ArgumentName(name="secureMessage") SecureMessage secureMessage);
	
	public int encrypt(@ArgumentName(name="secureMessage") SecureMessage secureMessage);
	
	public int getAdditionalDecryptionKeyAcceptanceList(@ArgumentName(name="domain") String domain,
			@ArgumentName(name="additionalDecryptionKeyAcceptanceList") Set additionalDecryptionKeyAcceptanceList);
	
	public int getAdditionalDecryptionKeyAliases(@ArgumentName(name="domain") String domain, @ArgumentName(name="additionalDecryptionKeyAliases") Set additionalDecryptionKeyAliases);
	
	public int isPassphraseExpired(@ArgumentName(name="expired") BooleanHolder expired);
	
	public int setParameter(@ArgumentName(name="key") String key, @ArgumentName(name="value") String value);
	
	public int verifyFile(@ArgumentName(name="signer") String signer,
			@ArgumentName(name="filePath") String filePath,
			@ArgumentName(name="signature") String signature,
			@ArgumentName(name="validSigners") Set validSigners,
			@ArgumentName(name="invalidSigners") Set invalidSigners);
	
	public int verifyCleartextSignedMessage(@ArgumentName(name="signer") String signer,
			@ArgumentName(name="signedMessage") String signedMessage,
			@ArgumentName(name="validSigners") Set validSigners,
			@ArgumentName(name="invalidSigners") Set invalidSigners,
			@ArgumentName(name="signature") StringHolder content);

	public int signFile(@ArgumentName(name="filePath") String filePath, @ArgumentName(name="signature") StringHolder signature);
	
	public int signText(@ArgumentName(name="filePath") String filePath, @ArgumentName(name="detached") boolean detached, @ArgumentName(name="signature") StringHolder signature);

}
