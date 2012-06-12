package com.hush.hee.keyserver;

import java.util.Date;

import com.hush.hee.BadRequestException;
import com.hush.hee.DeniedException;
import com.hush.hee.KeyStoreException;
import com.hush.hee.NotFoundException;

public interface Keyserver
{
	public void activateUser(String userAlias, String activationCode)
			throws KeyStoreException, DeniedException,
			BadRequestException, NotFoundException;

	public void addAdministrator(String customerID, String userAlias)
			throws KeyStoreException, DeniedException,
			BadRequestException, NotFoundException;

	public void addDomain(String customerID, String domainName,
			Boolean requirePreactivation, Boolean requireActivationEmail)
			throws KeyStoreException, DeniedException,
			BadRequestException, NotFoundException;

	public void deleteUser(String userAlias) throws KeyStoreException,
			DeniedException, BadRequestException, NotFoundException;

	public String[] getAdditionalDecryptionKeyAcceptanceDomains(
			String domainName) throws KeyStoreException, DeniedException,
			BadRequestException;

	public String[] getAdditionalDecryptionKeyAliases(String domainName)
			throws KeyStoreException, DeniedException,
			BadRequestException, NotFoundException;

	public String getAuthenticatedUser();

	public MailServerInformation getMailServerInformation(String userAlias)
			throws KeyStoreException, DeniedException,
			BadRequestException, NotFoundException;

	public String getPassphraseComponent(String userAlias)
			throws KeyStoreException, DeniedException,
			BadRequestException, NotFoundException;

	public Date getPassphraseExpirationTime(String userAlias)
			throws KeyStoreException, DeniedException,
			BadRequestException, NotFoundException;

	public String getPrivateAliasDefinition(String userAlias)
			throws KeyStoreException, DeniedException,
			BadRequestException, NotFoundException;

	public PrivateKeyInformation getPrivateKeyInformation(
			String privateUserAlias, Boolean allKeys) throws KeyStoreException,
			DeniedException, BadRequestException, NotFoundException;

	public PublicKeyInformation getPublicKeyInformation(String userAlias,
			String keyID, boolean includeAdks) throws KeyStoreException, DeniedException,
			BadRequestException;

	public void removeAdministrator(String customerID, String userAlias)
			throws KeyStoreException, DeniedException,
			BadRequestException, NotFoundException;

	public void reserveUser(String userAlias, String reservationCode)
			throws KeyStoreException, DeniedException,
			BadRequestException, NotFoundException;

	public void changeEmailPassword(String userAlias,
			String emailPassword, String newEmailPassword)
			throws KeyStoreException, DeniedException,
			BadRequestException, NotFoundException;

	public void savePassphraseComponent(String userAlias,
			String passphraseComponent) throws KeyStoreException,
			DeniedException, BadRequestException, NotFoundException;

	public void savePassphraseExpirationTime(String userAlias,
			Date passphraseExpirationTime) throws KeyStoreException,
			DeniedException, BadRequestException, NotFoundException;

	public void savePrivateAliasDefinition(String userAlias,
			String privateAliasDefinition) throws KeyStoreException,
			DeniedException, BadRequestException, NotFoundException;

	public void savePrivateKeyInformation(String privateUserAlias,
			String newPrivateUserAlias, com.hush.hee.keyserver.PrivateKey[] privateKeys,
			String randomSeed, Boolean addKeys) throws KeyStoreException,
			DeniedException, BadRequestException, NotFoundException;

	public void savePublicKeyInformation(String userAlias,
			PublicKey[] publicKeys, String reservationCode, String customerID,
			String applicationID, String privateAliasDefinition,
			String encryptionMethod, String passphraseComponent)
			throws KeyStoreException, DeniedException,
			BadRequestException, NotFoundException;

	public void setAliasActivationStatus(String userAlias, Boolean active)
			throws KeyStoreException, DeniedException,
			BadRequestException, NotFoundException;

	public void setAuthenticatedUser(String userAlias);
}
