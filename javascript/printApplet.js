/**
 * Param "code" is the applet class that provides the main execution thread.
 *
 * Param "updateKeyserver" is the hostname of the keyserver to which you wish to
 * connect.  It shoud be a keyserver that can be used for read and write actions.
 *
 * Param "customerID" is your customer ID, which you receive from your Hush
 * representative.
 *
 * Param "version" is is an array with four version numbers,
 * such as "new Array(2,1,0,31)" - it ensures automatic update of locally
 * installed  files.
 *
 * Param "onAppletLoaded" specifies JavaScript to be run when the applet
 * is loaded and ready for use.
 *
 * Param "disableLocalInstallForMsie" only needs to be false if the user
 * is using IE and does not have the correct permissions        - rare occurence
 * usually only encountered when Windows emulators are run on UNIX machines
 *
 * Param "disableJarForMsie" should be set to true only if you're worried
 * about the user being forced to download the Jar as well as the CAB if the
 * VM searches for a class not in the CAB.      Really only an issue for users
 * who communicate with users of PGP software that uses algorithms we don't
 * implement. If you set this, the Sun Java Plug-in will not work with IE.
 *
 * Param "useSunPluginForMsie" should be set to true if you wish to
 * auto-install the Sun Java Plug-in. Setting this parameter renders
 * the previous parameter irrelevant.
 *
 * Param "pgpMessageHeader" is the header to be used on PGP messages.
 * May be null.
 *
 * Param "pgpSignatureHeader" is the header to be used on PGP signatures.
 * May be null.
 *
 * Param "lookupKeyserver" is the hostname of a keyserver to be used for
 * all read-only operations.  If null, updateKeyserver will be used.
 *
 * Param "keyserverConnectTimeout" is the amount of time before a keyserver
 * connection times out.  Effective only in Java 1.4 and higher.  May be null.
 *
 * Param "keyserverConnectTimeout" is the amount of time before a keyserver
 * read times out.  Effective only in Java 1.4 and higher.  May be null.
 *
 * Param "codebase" is the URL from which Java files will be loaded.  May be
 * null.  Defaults to "../shared".
 *
 * Param "onStopUrl" is a URL that will be accessed when the applet is
 * "Stop"-ed.  May be null.
 *
 * Param "randomSeedUpdateCycle" is the number of seconds between updates
 * of the random seed stored with the key record.  If null or -1, timed
 * updates will not be performed.
 *
 * Param "forgiveBadRandomSeed" indicates that authentication will not
 * fail if the random seed is missing or corrupt.  A warning will be
 * shown on the Java console.
 *
 * Param "privateAliasHashAlgorithm" sets default hash for new account
 * private aliases.
 *
 * Param "privateAliasIterationCount" sets the iteration count for new
 * account private aliases.
 *
 * Param "newSigningKeyAlgorithm" sets the algorithm for new signature keys.
 *
 * Param "newSigningKeySize" sets the size for new signature keys.
 *
 * Param "newEncryptionKeyAlgorithm" sets the algorithm for new encryption keys.
 *
 * Param "newEncryptionKeySize" sets sets the size for new encryption keys.
 *
 * Param "newKeySignatureHashAlgorithm" sets the hash algorithm for the
 * signatures on the new keys.
 *
 * Param "signatureHashAlgorithm" sets the algorithm that will be used when
 * signing outgoing messages.
 * 
 * Param "generatedPasswordEmailSubjectTemplate" is the subject template to be
 * used when sending emails (to the password keeper) encrypted with
 * generated passwords.  The following fields will be replaced: %MESSAGEID%,
 * %EMAILRECIPIENT%, %PASSWORD%, %NOTES%.
 *
 * Param "generatedPasswordEmailSubjectTemplate" is the body template to be
 * used when sending emails (to the password keeper) encrypted with
 * generated passwords.  The following fields will be replaced: %MESSAGEID%,
 * %EMAILRECIPIENT%, %PASSWORD%, %NOTES%.
 *
 * Param "signPublicKeyLookupRequests" can be used if information in public key
 * lookup responses will contain customer-private data, such as the
 * generated password email recipient.
 */
function getPrintAppletObject()
{
	var printApplet = new Object();
	
	printApplet.codebase = "../shared/";
	printApplet.randomSeedUpdateCycle = -1;
	printApplet.isMsie = false;
	printApplet.isNetscape4x = false;
	printApplet.useProgressIndicators = true;
	printApplet.generatedPasswordEmailSubjectTemplate = "[%MESSAGEID%] Your recent email to %EMAILRECIPIENT%";
	printApplet.generatedPasswordEmailBodyTemplate = "You recently sent an email to %EMAILRECIPIENT%, which was\r\nencrypted using the following password:\r\n\r\n\t%PASSWORD%\r\n\r\nThe message you sent was assigned the following message id:\r\n\r\n\t%MESSAGEID%\r\n\r\n%NOTES%\r\n";
	printApplet.signPublicKeyLookupRequests = false;
	
	printApplet._params = new Array();

	// You can override this in your object
	printApplet.error = function(message)
	{
		alert(message);
	}

	// You can create your own log function too.
	printApplet.log = function(message)
	{
		
	}

	printApplet.addParam = function(name, value)
	{
		var param = new Object();
		param.name = name;
		param.value = value == null ? "" : value;
		this._params[this._params.length] = param;
	}

	printApplet.validate = function()
	{
		if ( this.codebase.length > 0 && this.codebase.substring
			(this.codebase.length - 1, this.codebase.length ) != "/" )
		{
			this.codebase += "/";
		}

		if (navigator.appName == "Microsoft Internet Explorer")
		{
			this.isMsie = true;
		}
		else if (navigator.appName == "Netscape"
			&& navigator.userAgent.indexOf("Gecko") == -1 )
		{
			this.isNetscape4x = true;
			this.error("Warning! You are using a very old version of Netscape. "
			+ "This version is no longer officially supported and has many "
			+ "unpatched security issues. You are advised to upgrade. Use of "
			+ "this browser may compromise the security of your communications.");
		}
	}
	
	printApplet.print = function()
	{
		this.validate();
		
		
		var out = "";
		
		if ( this.isMsie && this.useSunPluginForMsie )
		{
			out += '<object '
				+ 'classid="clsid:8AD9C840-044E-11D1-B3E9-00805F499D93" '
				+ 'width="0" height="0" '
				+ 'codebase='
				+ '"http://java.sun.com/products/plugin/autodl/jinstall-1_4_0-win.cab'
				+ '#Version=1,4,0,0"';
		}
		else
		{
			out += '<applet name="HushEncryptionEngine"'
				+ ' code="' + this.code + '"'
				+ ' codebase="' + this.codebase + '" mayscript width=0 height=0 viewastext';
			if (this.isNetscape4x)
			{
				out += ' archive="' + this.codebase
					+ 'HushEncryptionEngineNS4.jar"';
			}
			else if ( ! this.isMsie || ! this.disableJarForMsie )
			{
				out += ' archive="' + this.codebase + 'HushEncryptionEngine.jar"';
			}
		}
		
		out += '>';
		
		if ( this.isMsie && ! this.useSunPluginForMsie )
		{
			if (this.disableLocalInstallForMsie)
			{
				this.addParam("cabbase", this.codebase + "HushEncryptionEngine.cab");
			}
			else
			{
				this.addParam("useslibrary", "HushEncryptionEngine3a");
				this.addParam("namespace", "HushEncryptionEngine3a");
				this.addParam("useslibrarycodebase", this.codebase + "HushEncryptionEngine.cab");
				this.addParam("useslibraryversion", this.version[0] + "," + this.version[1]
					+ "," + this.version[2] + "," + this.version[3]);
			}
		}
		
		if ( this.isMsie && this.useSunPluginForMsie )
		{
			this.addParam("code", this.code);
			this.addParam("type", "application/x-java-applet;jpi-version=1.4");
			this.addParam("scriptable", "true");
		}
		
		// These parameters are used by the Sun Java Plug-in.
		// We will write them for all - they will be ignored by others.
		this.addParam("cache_option", "Plugin");
		this.addParam("cache_archive", this.codebase + "HushEncryptionEngine.jar");
		this.addParam("cache_version", this.version[0] + "." + this.version[1]
					+ "." + this.version[2] + "." + this.version[3]);

		// These are parameters used by the HushEncryptionEngine itself
		this.addParam("keyserver", this.updateKeyserver);
		this.addParam("updateKeyservers", this.updateKeyserver);
		this.addParam("customerID", this.customerID);
		this.addParam("useProgressIndicators", this.useProgressIndicators);
		this.addParam("onLoad", this.onAppletLoaded);
		this.addParam("randomSeedUpdateCycle", this.randomSeedUpdateCycle);

		if (this.lookupKeyserver != null)
			this.addParam("lookupKeyservers", this.lookupKeyserver);
		
		if (this.keyserverConnectTimeout != null)
			this.addParam("connectTimeout", this.keyserverConnectTimeout);
		
		if (this.keyserverReadTimeout != null)
			this.addParam("readTimeout", this.keyserverReadTimeout);
			
		if (this.pgpMessageHeader != null)
			this.addParam("pgpMessageHeader", this.pgpMessageHeader);
			
		if (this.pgpSignatureHeader != null)
			this.addParam("pgpSignatureHeader", this.pgpSignatureHeader);
		
		if (this.onStopUrl != null)
			this.addParam("onStopUrl", this.onStopUrl);
		
		if (this.forgiveBadRandomSeed == true)
			this.addParam("forgiveBadRandomSeed", "true");

	        if (this.privateAliasHashAlgorithm != null)
			this.addParam("newPrivateAliasHashAlgorithm", this.privateAliasHashAlgorithm);

        	if (this.privateAliasIterationCount != null)
			this.addParam("newPrivateAliasIterationCount", this.privateAliasIterationCount);
			
	        if (this.newSigningKeyAlgorithm != null)
			this.addParam("newSigningKeyAlgorithm", this.newSigningKeyAlgorithm);
        
		if (this.newSigningKeySize != null)
			this.addParam("newSigningKeySize", this.newSigningKeySize);
        
		if (this.newEncryptionKeyAlgorithm != null)
			this.addParam("newEncryptionKeyAlgorithm", this.newEncryptionKeyAlgorithm);
        
		if (this.newEncryptionKeySize != null)
			this.addParam("newEncryptionKeySize", this.newEncryptionKeySize);

	        if (this.newKeySignatureHashAlgorithm != null)
			this.addParam("newKeySignatureHashAlgorithm", this.newKeySignatureHashAlgorithm);

		if (this.signatureHashAlgorithm != null)
			this.addParam("signatureHashAlgorithm", this.signatureHashAlgorithm);

		if (this.signPublicKeyLookupRequests == true)
			this.addParam("signPublicKeyLookupRequests", "true");

		if (this.generatedPasswordEmailSubjectTemplate != null)
			this.addParam("generatedPasswordEmailSubjectTemplate", this.generatedPasswordEmailSubjectTemplate);

		if (this.generatedPasswordEmailBodyTemplate != null)
			this.addParam("generatedPasswordEmailBodyTemplate", this.generatedPasswordEmailBodyTemplate);

		for (var i = 0; i < this._params.length; i++)
		{
			out += "	<param name=\"" + this._params[i].name
				+ "\" value=\"" + this._params[i].value + "\">\r\n";
		} 
		
		if (this.isMsie && this.useSunPluginForMsie)
			out += '</object>';
		else
			out += '</applet>';
		
		this.log(out);

		document.write(out);
	}

	return printApplet;
}

function printApplet(code, updateKeyserver,
        customerID, version, onAppletLoaded,
        disableLocalInstallForMsie, disableJarForMsie, useSunPluginForMsie,
        pgpMessageHeader, pgpSignatureHeader, lookupKeyserver,
        keyserverConnectTimeout, keyserverReadTimeout, codebase, onStopUrl,
        randomSeedUpdateCycle, forgiveBadRandomSeed, privateAliasHashAlgorithm,
        privateAliasIterationCount,
        newSigningKeyAlgorithm, newSigningKeySize,
        newEncryptionKeyAlgorithm, newEncryptionKeySize,
        newKeySignatureHashAlgorithm,
        signatureHashAlgorithm
        )
{
        var pi = getPrintAppletObject();
        pi.code = code;
        pi.updateKeyserver = updateKeyserver;
        pi.customerID = customerID;
        pi.version = version;
        pi.onAppletLoaded = onAppletLoaded;
        pi.disableLocalInstallForMsie = disableLocalInstallForMsie;
        pi.disableJarForMsie = disableJarForMsie;
        pi.useSunPluginForMsie = useSunPluginForMsie;
        pi.pgpMessageHeader = pgpMessageHeader;
        pi.pgpSignatureHeader = pgpSignatureHeader;
        pi.lookupKeyserver = lookupKeyserver;
        pi.keyserverConnectTimeout = keyserverConnectTimeout;
        pi.keyserverReadTimeout = keyserverReadTimeout;
        if ( codebase != null )
          pi.codebase = codebase;
        pi.onStopUrl = onStopUrl;
        if ( randomSeedUpdateCycle != null )
          pi.randomSeedUpdateCycle = randomSeedUpdateCycle;
        pi.forgiveBadRandomSeed = forgiveBadRandomSeed;
	pi.privateAliasHashAlgorithm = privateAliasHashAlgorithm;
	pi.privateAliasIterationCount = privateAliasIterationCount;
	pi.newSigningKeyAlgorithm = newSigningKeyAlgorithm;
	pi.newSigningKeySize = newSigningKeySize;
	pi.newEncryptionKeyAlgorithm = newEncryptionKeyAlgorithm;
	pi.newEncryptionKeySize = newEncryptionKeySize;
	pi.newKeySignatureHashAlgorithm = newKeySignatureHashAlgorithm;
	pi.signatureHashAlgorithm = signatureHashAlgorithm;
        pi.print();
}






