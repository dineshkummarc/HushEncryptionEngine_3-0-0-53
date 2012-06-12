package com.hush.hee;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.Serializable;

import com.hush.pgp.PgpConstants;
import com.hush.util.Base64;
import com.hush.util.Conversions;

public class SecureMessage implements Serializable
{	
	private static final long serialVersionUID = 3824638748597947819L;
	
	private String characterEncoding = "UTF-8";
	private InputStream inputStream;
	private OutputStream outputStream;
	private byte[] outputBytes;
	private byte[] inputBytes;
	private String signerAlias;
	private String[] detachedSignatures;
	private QuestionAndAnswer[] questionsAndAnswers;
	private String[] certificateStringArray;
	private byte[][] passwords;
	private String[] aliases;
	private boolean useArmor;
	private boolean anonymous;
	private String[] validSigners;
	private String[] invalidSigners;
	private String authInfo;
	private boolean publicKeyEncryptionOnly;
	private String notes = "";
	private String generatedPassword;
	private String generatedPasswordSalt;
	private String generatedPasswordHash;
	private String generatedPasswordEncryptionKey;
	private String generatedPasswordMessageID;
	private String[] onePassSignatures;
	
	/**
	 * Will never return null, just a 0 length array.
	 * 
	 * @return Returns the onePassSignatures.
	 */
	public String[] getOnePassSignatures()
	{
		if ( onePassSignatures == null ) return new String[0];
		return onePassSignatures;
	}

	/**
	 * @param onePassSignatures The onePassSignatures to set.
	 */
	public void setOnePassSignatures(String[] onePassSignatures)
	{
		this.onePassSignatures = onePassSignatures;
	}

	/**
	 * @return Returns the generatedPassword.
	 */
	public String getGeneratedPassword()
	{
		return generatedPassword;
	}

	/**
	 * @param generatedPassword The generatedPassword to set.
	 */
	public void setGeneratedPassword(String generatedPassword)
	{
		this.generatedPassword = generatedPassword;
	}

	/**
	 * @return Returns the notes.
	 */
	public String getNotes()
	{
		return notes;
	}

	/**
	 * @param notes The notes to set.
	 */
	public void setNotes(String notes)
	{
		this.notes = notes;
	}

	/**
	 * @return Returns the publicKeyOnly.
	 */
	public boolean getPublicKeyEncryptionOnly()
	{
		return publicKeyEncryptionOnly;
	}

	/**
	 * @param publicKeyOnly The publicKeyOnly to set.
	 */
	public void setPublicKeyEncryptionOnly(boolean publicKeyEncryptionOnly)
	{
		this.publicKeyEncryptionOnly = publicKeyEncryptionOnly;
	}

	/**
	 * Set the character encoding to be used in encryption or signing operation.
	 * @param characterEncoding the character encoding to use
	 */
	public void setCharacterEncoding(String characterEncoding)
	{
		this.characterEncoding = characterEncoding;
	}
	
	/**
	 * Retrieve the character encoding to be used in encryption and signing operations.
	 * @return the character encoding
	 */
	public String getCharacterEncoding()
	{
		return characterEncoding;
	}
	
	/**
	 * Set the input stream to be used in encryption, decryption, signing and verification
	 * operations.
	 * @param inputStream the input stream
	 */
	public void setInputStream(InputStream inputStream)
	{
		this.inputBytes = null;
		this.inputStream = inputStream;
	}

	/**
	 * Retrieve the input stream
	 * @return the input stream
	 */
	public InputStream getInputStream()
	{
		return inputStream;
	}
	
	/**
	 * Set the input bytes to be used in an encryption, decryption, signing
	 * or verification operation.
	 * @param inputBytes the input bytes
	 */
	public void setInputBytes(byte[] inputBytes)
	{
		this.inputStream = null;
		this.inputBytes = inputBytes;
	}
	
	/**
	 * Retrieve the input bytes to be used in an encryption, decryption,
	 * signing or verification operation.
	 * @return the input bytes
	 */
	public byte[] getInputBytes()
	{
		return this.inputBytes;
	}
	
	
	/**
	 * Set an output stream which will be used to output the results of
	 * any encryption or signing operations.  If this has not been set,
	 * the results of encryption and signing operations will be accessible
	 * using the getOutputBytes() method.
	 * @param outputStream the output stream
	 */
	public void setOutputStream(OutputStream outputStream)
	{
		this.outputStream = outputStream;
	}
	
	/**
	 * Retrieve the output stream.  Use this method if you have
	 * set an output stream using setOutputStream;
	 * @return the output stream
	 */
	public OutputStream getOutputStream()
	{
		return outputStream;
	}
	
	/**
	 * Retrieve the output bytes. Use this method if you have not set an output
	 * stream using setOutputStream.
	 * @return the encrypted or signed bytes.
	 */
	public byte[] getOutputBytes()
	{
		return outputBytes;
	}
	
	/**
	 * Set the output bytes.
	 * @param outputBytes
	 */
	protected void setOutputBytes(byte[] outputBytes)
	{
		this.outputBytes = outputBytes;
	}
	
	/**
	 * Set the expected signer prior to verifying a digital signature.
	 * @param signer the expected signer
	 */
	public void setSignerAlias(String signerAlias)
	{
		this.signerAlias = signerAlias;
	}
	
	/**
	 * Retrieve the expected signer to be used when verifying digital signatures.
	 * @return the signer's alias
	 */
	public String getSignerAlias()
	{
		return signerAlias;
	}
	
	/**
	 * Set the digital signature of the plaintext to to verified. 
	 * @param detachedSignature the detached signature
	 */
	public void setDetachedSignatures(String[] detachedSignatures)
	{
		this.detachedSignatures = detachedSignatures;
	}
	
	/**
	 * Retrieve the detached signatures produced by the most recent
	 * signing operation or set by setDetachedSignatures().
	 * 
	 * Will never return null, just a 0 length array.
	 * 
	 * @return the detached signatures.
	 */
	public String[] getDetachedSignatures()
	{
		if ( detachedSignatures == null ) return new String[0];
		return detachedSignatures;
	}
	
	/**
	 * Set the questions and answers (and their associated recipients) to
	 * be used during an encryption operation.
	 * @param questionsAndAnswers the questions and answers
	 */
	public void setQuestionsAndAnswers(QuestionAndAnswer[] questionsAndAnswers)
	{
		this.questionsAndAnswers = questionsAndAnswers;
	}

	/**
	 * Retrieve the questions and answers set by setQuestionsAndAnswers().
	 * 
	 * Will never return null, just a 0 length array.
	 * 
	 * @return
	 */
	public QuestionAndAnswer[] getQuestionsAndAnswers()
	{
		if ( questionsAndAnswers == null ) return new QuestionAndAnswer[0];
		return questionsAndAnswers;
	}
	
	/**
	 * Set the certificates to be used during an encryption operation.
	 * @param certificates the certificates
	 */
	public void setCertificates(String[] certificates)
	{
		this.certificateStringArray = certificates;
	}
	
	/**
	 * Retrieve the certificates set by setCertificates().
	 * 
	 * Will never return null, just a 0 length array.
	 * 
	 * @return the certificates
	 */
	public String[] getCertificates()
	{
		if ( certificateStringArray == null ) return new String[0];
		return certificateStringArray;
	}
	
	/**
	 * Set the passwords to be used during an encryption operation.
	 * @param passwords the passwords
	 */
	public void setPasswords(byte[][] passwords)
	{
		this.passwords = passwords;
	}
	
	/**
	 * Retrieve the passwords set by setPasswords().
	 * 
	 * Will never return null, just a 0 length array.
	 * 
	 * @return the passwords
	 */
	public byte[][] getPasswords()
	{
		if ( passwords == null ) return new byte[0][];
		return passwords;
	}
	
	/**
	 * Set the aliases to use during an encryption operation.  If public keys
	 * are available on the key server, they will be used.  If another 
	 * encryption method is determined by the key server, it will be used
	 * instead.
	 * @param recipientAliases
	 */
	public void setRecipientAliases(String[] recipientAliases)
	{
		this.aliases = recipientAliases;
	}
	
	/**
	 * Retrieve the aliases set by setAliases().
	 * 
	 * Will never return null, just a 0 length array.
	 * 
	 * @return the aliases
	 */
	public String[] getRecipientAliases()
	{
		if ( aliases == null ) return new String[0];
		return aliases;
	}
	
	/**
	 * Set whether or not this message will be armored.
	 * @param useArmor
	 */
	public void setUseArmor(boolean useArmor)
	{
		this.useArmor = useArmor;
	}
	
	/**
	 * Retrieve the armor setting set by setArmor().
	 * @return the armor setting
	 */
	public boolean getUseArmor()
	{
		return useArmor;
	}

	/**
	 * Set whether or not this message will be encrypted anonymously.
	 * @param anonymous
	 */
	public void setAnonymous(boolean anonymous)
	{
		this.anonymous = anonymous;
	}
	
	/**
	 * Retrieve the anonymous encryption setting set by setAnonymous().
	 * @return the anonymous encryption setting
	 */
	public boolean getAnonymous()
	{
		return anonymous;
	}
	
	/**
	 * Set the verified signers resulting from a verification operation.
	 * 
	 * @param validSigners
	 */
	protected void setValidSigners(String[] validSigners)
	{
		this.validSigners = validSigners;
	}
	
	/**
	 * Retrieve the verified signers after digital signature verification.
	 * 
	 * Will never return null, just a 0 length array.
	 * 
	 * @return the verified signers
	 */
	public String[] getValidSigners()
	{
		if ( validSigners == null ) return new String[0];
		return validSigners;
	}
	
	/**
	 * Set the failed signers resulting from a verification operation.
	 * @param invalidSigners
	 */
	protected void setInvalidSigners(String[] invalidSigners)
	{
		this.invalidSigners = invalidSigners;
	}
	
	/**
	 * Retrieve the failed signers after digital signature verification.
	 * 
	 * Will never return null, just a 0 length array.
	 * 
	 * @return the failed signers
	 */
	public String[] getInvalidSigners()
	{
		if ( invalidSigners == null ) return new String[0];
		return invalidSigners;
	}
	
	/**
	 * Set the authInfo xml data
	 * @param authInfo the authInfo field
	 */
	public void setAuthInfo(String authInfo)
	{
		this.authInfo = authInfo;
	}
	
	public boolean hasAuthInfo()
	{
		return authInfo != null;
	}
	
	/**
	 * Retrieve the authInfo information for use with Hushmail Express.
	 * @return authInfo xml
	 */
	public String getAuthInfo()
	{
		return authInfo;
	}

	public String getAuthInfoEmailHeaderName()
	{
		return AuthInfo.EMAIL_HEADER_NAME;
	}
	
	public String getAuthInfoEmailHeaderValue()
	{
		if (authInfo == null)
			return null;
		byte[] authInfoBytes = Conversions.stringToByteArray(authInfo,
				PgpConstants.UTF8);
		return Conversions.byteArrayToString(authInfo == null ? null : Base64
				.encode(authInfoBytes, 0, authInfoBytes.length, false),
				PgpConstants.UTF8);
	}
	
	/**
	 * @return Returns the generatedPasswordEncryptionKey.
	 */
	public String getGeneratedPasswordEncryptionKey()
	{
		if (this.generatedPassword == null || this.generatedPassword.equals(""))
			return null;
		
		if (this.generatedPasswordEncryptionKey == null)
		{
			setGeneratedPasswordEncryptionKey(
				PasswordUtils.generateEncryptionKey(getGeneratedPasswordSalt(), this.generatedPassword)
				);
		}
		
		return generatedPasswordEncryptionKey;
	}

	/**
	 * @param generatedPasswordEncryptionKey The generatedPasswordEncryptionKey to set.
	 */
	public void setGeneratedPasswordEncryptionKey(
			String generatedPasswordEncryptionKey)
	{
		this.generatedPasswordEncryptionKey = generatedPasswordEncryptionKey;
	}

	/**
	 * @return Returns the generatedPasswordHash.
	 */
	public String getGeneratedPasswordHash()
	{
		if (this.generatedPassword == null || this.generatedPassword.equals(""))
			return null;

		if (generatedPasswordHash == null)
		{
			setGeneratedPasswordHash(PasswordUtils.generatePasswordHash(getGeneratedPasswordEncryptionKey()));
		}

		return generatedPasswordHash;
	}

	/**
	 * @param generatedPasswordHash The generatedPasswordHash to set.
	 */
	public void setGeneratedPasswordHash(String generatedPasswordHash)
	{
		this.generatedPasswordHash = generatedPasswordHash;
	}

	/**
	 * @return Returns the generatedPasswordSalt.
	 */
	public String getGeneratedPasswordSalt()
	{
		if (this.generatedPassword == null || this.generatedPassword.equals(""))
			return null;

		if (generatedPasswordSalt == null)
		{
			setGeneratedPasswordSalt(
				PasswordUtils.generateAnswerSalt());
		}
		return generatedPasswordSalt;
	}

	/**
	 * @param generatedPasswordSalt The generatedPasswordSalt to set.
	 */
	public void setGeneratedPasswordSalt(String generatedPasswordSalt)
	{
		this.generatedPasswordSalt = generatedPasswordSalt;
	}

	public String getGeneratedPasswordMessageID()
	{
		return generatedPasswordMessageID;
	}

	public void setGeneratedPasswordMessageID(String generatedPasswordMessageID)
	{
		this.generatedPasswordMessageID = generatedPasswordMessageID;
	}
	
}