package com.hush.hee.net;

import java.io.IOException;
import java.io.Serializable;
import java.security.SecureRandom;
import java.util.Date;

import com.hush.hee.BadRequestException;
import com.hush.hee.DeniedException;
import com.hush.hee.KeyStoreException;
import com.hush.hee.keyserver.Keyserver;
import com.hush.hee.keyserver.MailServerInformation;
import com.hush.hee.keyserver.PrivateKey;
import com.hush.hee.keyserver.PrivateKeyInformation;
import com.hush.hee.keyserver.PublicKey;
import com.hush.hee.keyserver.PublicKeyInformation;
import com.hush.pgp.Key;
import com.hush.util.ExceptionWrapper;
import com.hush.util.Logger;
import com.hush.util.UnrecoverableKeyException;

public class KeyserverClient implements Keyserver, Serializable
{
	private static final long serialVersionUID = 2892549159583049342L;

	/**
	 * An array of key servers to be used for lookups. (Read-only.)
	 */
	private String[] lookupServerAddresses = new String[]{"keys1.hush.com"};

	/**
	 * An array of key servers to be used for updates.
	 */
	private String[] updateServerAddresses = new String[]{"keys1.hush.com"};

	/**
	 * A marker for the server currently in use for lookups.
	 */
	private int currentLookupServerIndex = 0;

	/**
	 * A marker for the server currently in use for updates.
	 */
	private int currentUpdateServerIndex = 0;

	/**
	 * A pseudo-random number generator for use by this class.
	 */
	private transient SecureRandom random;

	private String authenticatedUser;

	private Key privateKey;

	private boolean signPublicKeyLookupRequests = false;

	public String getAuthenticatedUser()
	{
		return authenticatedUser;
	}

	public void setAuthenticatedUser(String authenticatedAlias)
	{
		this.authenticatedUser = authenticatedAlias;
	}

	private Key getPrivateKey()
	{
		return privateKey;
	}

	public void setPrivateKey(Key privateKey)
	{
		this.privateKey = privateKey;
	}

	private void executeRequest(Request request, boolean readOnly)
			throws KeyStoreException
	{
		executeRequest(request, readOnly, false, null, null);
	}

	private void executeRequest(Request request, boolean readOnly,
			boolean signRequests, String signerAlias,
			com.hush.pgp.Key privateKey) throws KeyStoreException
	{
		if (readOnly && lookupServerAddresses == null)
			throw new KeyStoreException("No lookupKeyserver is set");

		if (!readOnly && updateServerAddresses == null)
			throw new KeyStoreException("No updateKeyserver is set");

		RequestConnection connection = null;
		int nowTryingThisServer;
		int firstServerTried;
		if (readOnly)
		{
			nowTryingThisServer = currentLookupServerIndex;
			firstServerTried = currentLookupServerIndex;
		}
		else
		{
			nowTryingThisServer = currentUpdateServerIndex;
			firstServerTried = currentUpdateServerIndex;
		}
		do
		{
			String server = readOnly ? lookupServerAddresses[nowTryingThisServer]
					: updateServerAddresses[nowTryingThisServer];
			try
			{
				connection = createRequestConnection(signRequests, server,
						request, signerAlias, privateKey, random);
				connection.execute();
				if (readOnly)
					currentLookupServerIndex = nowTryingThisServer;
				else
					currentUpdateServerIndex = nowTryingThisServer;

				return;
			}
			catch (IOException e)
			{
				Logger.logThrowable(this, Logger.ERROR, "Failed to connect to: "
						+ server, e);
			}
			if (++nowTryingThisServer == (readOnly ? lookupServerAddresses.length
					: updateServerAddresses.length))
				nowTryingThisServer = 0;
		}
		while (nowTryingThisServer != firstServerTried);
		throw new UnableToConnectToKeyserverException("Unable to connect to any key server");
	}

	/**
	 * This is protected for use by the mock object, FakeKeyManagmentServices.
	 */
	private RequestConnection createRequestConnection(boolean signRequests,
			String server, Request request, String alias, Key privateKey,
			SecureRandom random)
	{
		if (signRequests)
		{
			return new SignedRequestConnection(server, request, alias,
					privateKey, random);
		}
		else
		{
			return new RequestConnection(server, request);
		}
	}

	private String getNonce(boolean forReadOnlyOperation)
			throws KeyStoreException
	{
		RequestNonce nonceReq = new RequestNonce();
		executeRequest(nonceReq, forReadOnlyOperation);
		return (nonceReq.getNonce());
	}

	public void addAdministrator(String customerID, String userAlias)
			throws KeyStoreException, DeniedException, BadRequestException
	{
		AddAdministratorRequest request = new AddAdministratorRequest(
				customerID, userAlias);
		executeRequest(request, false, true, getAuthenticatedUser(), getPrivateKey());
	}

	public void addDomain(String customerID, String domainName,
			Boolean requirePreactivation, Boolean requireActivationEmail)
			throws KeyStoreException, DeniedException, BadRequestException
	{
		AddDomainRequest request = new AddDomainRequest(domainName, customerID,
				requireActivationEmail.booleanValue(), requirePreactivation
						.booleanValue());
		executeRequest(request, false, true, getAuthenticatedUser(), getPrivateKey());
	}

	public String[] getAdditionalDecryptionKeyAcceptanceDomains(
			String domainName) throws KeyStoreException, DeniedException, BadRequestException
	{
		AdkAcceptanceLookupRequest req = new AdkAcceptanceLookupRequest(
				domainName);
		executeRequest(req, true);
		return req.getDomains();
	}

	public String[] getAdditionalDecryptionKeyAliases(String domainName)
			throws KeyStoreException, DeniedException, BadRequestException
	{
		AdkLookupRequest req = new AdkLookupRequest(domainName);
		executeRequest(req, true);
		return req.getAliases();
	}

	public MailServerInformation getMailServerInformation(String userAlias)
			throws KeyStoreException, DeniedException, BadRequestException
	{
		MailServerLookupRequest request = new MailServerLookupRequest(
				authenticatedUser);
		executeRequest(request, true);
		MailServerInformation info = new MailServerInformation();
		info.setEmailHostname(request.getMailStorageAddress());
		info.setEmailUsername(request.getMailserverUID());
		info.setEncryptedEmailPassword(request.getMailserverPassword());
		return info;
	}

	public void changeEmailPassword(String userAlias,
			String emailPassword, String newEmailPassword)
			throws KeyStoreException, DeniedException, BadRequestException
	{
		MailServerUpdateRequest request = new MailServerUpdateRequest(
				userAlias, emailPassword, newEmailPassword);
		executeRequest(request, false);
	}

	public String getPrivateAliasDefinition(String userAlias)
			throws KeyStoreException, DeniedException, BadRequestException
	{
		PrivateAliasDefinitionLookupRequest defLookup = new PrivateAliasDefinitionLookupRequest(
				userAlias);
		executeRequest(defLookup, true);
		return defLookup.getPrivateAliasDefinition();
	}

	public void savePrivateAliasDefinition(String userAlias,
			String privateAliasDefinition)
			throws KeyStoreException, DeniedException, BadRequestException
	{
		PrivateAliasDefinitionUpdateRequest request = new PrivateAliasDefinitionUpdateRequest(
				userAlias, privateAliasDefinition);
		executeRequest(request, false, true, getAuthenticatedUser(), getPrivateKey());
	}

	public PrivateKeyInformation getPrivateKeyInformation(
			String privateUserAlias, Boolean getAllKeys) throws KeyStoreException, DeniedException, BadRequestException
	{
		PrivateKeyInformation privateKeyInformation = new PrivateKeyInformation();
		PvKLookupRequest request = new PvKLookupRequest(privateUserAlias,
				getAllKeys, getNonce(true));
		
		executeRequest(request, true);
		
		privateKeyInformation.setEncryptedPrivateKeys(request.getPrivateKeys());
		privateKeyInformation.setLastAccessTime(request.getLastAccessTime());
		privateKeyInformation.setEncryptedRandomSeed(request.getRandomSeed());
		return privateKeyInformation;
	}

	public void savePrivateKeyInformation(String privateUserAlias,
			String newPrivateUserAlias, PrivateKey[] privateKeys,
			String randomSeed, Boolean addKeys) throws KeyStoreException,
			DeniedException, BadRequestException
	{
		PvKUpdateRequest request;
		request = new PvKUpdateRequest(privateUserAlias, newPrivateUserAlias,
				privateKeys, randomSeed, addKeys, getNonce(false));
		executeRequest(request, false);
	}

	public void activateUser(String userAlias, String activationCode)
			throws KeyStoreException, DeniedException, BadRequestException
	{
		PuKActivationRequest request = new PuKActivationRequest(userAlias,
				activationCode);
		executeRequest(request, false);
	}

	public void deleteUser(String userAlias) throws KeyStoreException,
			DeniedException, BadRequestException
	{
		PuKDeletionRequest request = new PuKDeletionRequest(userAlias);
		executeRequest(request, false, true, getAuthenticatedUser(), getPrivateKey());
	}

	public PublicKeyInformation getPublicKeyInformation(String userAlias,
			String keyID, boolean includeAdks) throws KeyStoreException, DeniedException, BadRequestException
	{
		PuKLookupRequest request = new PuKLookupRequest(userAlias, keyID, includeAdks);
		executeRequest(request, true, getSignPublicKeyLookupRequests()
				&& authenticatedUser != null, getAuthenticatedUser(),
				getPrivateKey());
		if ( request.getNotFound() ) return null;
		
		PublicKeyInformation publicKeyInformation = new PublicKeyInformation();
		publicKeyInformation.setGeneratedPassword(request
				.getGeneratedPassword());
		publicKeyInformation.setPassphraseComponent(new Boolean(request
				.getSharedSecret()));
		publicKeyInformation.setEncryptionMethod(request.getEncryptionMethod());
		publicKeyInformation.setPublicKeys(request.getPublicKeys());
		
		// TODO: use constants
		if (request.getGeneratedPassword() == null && userAlias != null)
		{
			if (request.isActive())
			{
				publicKeyInformation.setUserStatus("Active");
			}
			else if (request.isAwaitingActivationEmail())
			{
				publicKeyInformation.setUserStatus("Needs Activation");
			}
			else
			{
				throw new KeyStoreException("Unexpected user status");
			}
		}
		
		return publicKeyInformation;
	}

	public void reserveUser(String userAlias, String reservationCode) throws KeyStoreException, DeniedException, BadRequestException
	{
		PuKPreActivationRequest request = new PuKPreActivationRequest(
				userAlias, reservationCode, 0);
		executeRequest(request, false, true, getAuthenticatedUser(), getPrivateKey());
	}

	public void savePublicKeyInformation(String userAlias,
			PublicKey[] publicKeys, String reservationCode, String customerID,
			String applicationID, String privateAliasDefinition,
			String encryptionMethod, String passphraseComponent)
			throws KeyStoreException, DeniedException, BadRequestException
	{
		PuKUpdateRequest publicRequest;

		publicRequest = new PuKUpdateRequest(userAlias, publicKeys,
				reservationCode, customerID, applicationID,
				privateAliasDefinition, encryptionMethod, passphraseComponent);

		executeRequest(publicRequest, false);
	}

	public void removeAdministrator(String customerID, String userAlias)
			throws KeyStoreException, DeniedException, BadRequestException
	{
		RemoveAdministratorRequest request = new RemoveAdministratorRequest(
				customerID, userAlias);
		executeRequest(request, false, true, getAuthenticatedUser(), getPrivateKey());
	}

	public String getPassphraseComponent(String userAlias)
			throws KeyStoreException, DeniedException, BadRequestException
	{
		RetrievePassphraseComponentRequest request = new RetrievePassphraseComponentRequest(
				userAlias);
		executeRequest(request, true, true, getAuthenticatedUser(), getPrivateKey());
		return request.getPassphraseComponent();
	}

	public Date getPassphraseExpirationTime(String userAlias)
			throws KeyStoreException, DeniedException, BadRequestException
	{
		RetrievePassphraseExpirationTimeRequest request = new RetrievePassphraseExpirationTimeRequest(
				userAlias);
		executeRequest(request, true, true, getAuthenticatedUser(), getPrivateKey());
		if (request.getPassphraseExpirationTime() <= 0)
			return null;
		return new Date(request.getPassphraseExpirationTime()*1000);
	}

	public void savePassphraseComponent(String userAlias,
			String passphraseComponent) throws KeyStoreException,
			DeniedException, BadRequestException
	{
		SavePassphraseComponentRequest request = new SavePassphraseComponentRequest(
				userAlias, passphraseComponent);
		executeRequest(request, false, true, getAuthenticatedUser(), getPrivateKey());
	}

	public void savePassphraseExpirationTime(String userAlias,
			Date passphraseExpirationTime) throws KeyStoreException,
			DeniedException, BadRequestException
	{
		SetPassphraseExpirationTimeRequest request = new SetPassphraseExpirationTimeRequest(
				userAlias, passphraseExpirationTime == null ? 0
						: passphraseExpirationTime.getTime() / 1000);
		executeRequest(request, false, true, getAuthenticatedUser(), getPrivateKey());
	}

	public void setAliasActivationStatus(String userAlias, Boolean active)
			throws KeyStoreException, DeniedException, BadRequestException
	{
		if (active == null)
			throw new KeyStoreException("Null value not allowed");
		SetAliasActivationRequest request = new SetAliasActivationRequest(
				userAlias, active.booleanValue());
		executeRequest(request, false, true, getAuthenticatedUser(), getPrivateKey());
	}

	public boolean getSignPublicKeyLookupRequests()
	{
		return signPublicKeyLookupRequests;
	}

	public void setSignPublicKeyLookupRequests(
			boolean signPublicKeyLookupRequests)
	{
		this.signPublicKeyLookupRequests = signPublicKeyLookupRequests;
	}

	public String[] getUpdateServerAddresses()
	{
		return updateServerAddresses;
	}

	public void setUpdateServerAddresses(String[] updateServerAddresses)
	{
		this.updateServerAddresses = updateServerAddresses;
	}

	public String[] getLookupServerAddresses()
	{
		return lookupServerAddresses;
	}

	public void setLookupServerAddresses(String[] lookupServerAddresses)
	{
		this.lookupServerAddresses = lookupServerAddresses;
	}
}
