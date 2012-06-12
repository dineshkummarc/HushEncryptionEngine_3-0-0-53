VERSION1=3
VERSION2=0
VERSION3=0
VERSION4=53

MS_SPC=../../java_dependencies/certs/code-signing-cert-thawte-2009-06-09.spc
MS_PVK=../../java_dependencies/certs/code-signing-cert-thawte-2009-06-09.pvk

CLASSPATH=.:../java_dependencies/lib/netscape.jar:../java_dependencies/lib/microsoft.jar:../java_dependencies/lib/commons-logging-1.1.1.jar
#CLASSPATH=.\;../java_dependencies/lib/netscape.jar\;../java_dependencies/lib/microsoft.jar\;../java_dependencies/lib/commons-logging-1.1.1.jar

MS_SDK_BIN_DIR=/cygdrive/c/Program\ Files/Microsoft\ SDK\ for\ Java\ 4.0/bin

JVC=$(MS_SDK_BIN_DIR)/jvc
JAVADIR=/usr/lib/jvm/java-6-sun
WINJAVADIR=/usr/lib/jvm/java-6-sun
#JAVADIR=/cygdrive/c/Program\ Files/Java/jdk
#WINJAVADIR=c:\\Program\ Files\\Java\\jdk
JAVAC=$(JAVADIR)/bin/javac
JAVA=$(JAVADIR)/bin/java
JAVADOC=$(JAVADIR)/bin/javadoc
JAR=$(JAVADIR)/bin/jar
JARSIGNER=$(JAVADIR)/bin/jarsigner
TMP_JAR_1=HushEncryptionEngineTmp1.jar
TMP_JAR_2=HushEncryptionEngineTmp2.jar
PROGUARD=$(JAVA) -Xms128m -Xmx128m -classpath \
	.:proguard.jar \
	proguard.ProGuard @proguard.conf \
	-overloadaggressively \
	-dontusemixedcaseclassnames \
	-injars build/$(TMP_JAR_1) \
	-outjar build/$(TMP_JAR_2)

AXBRIDGE_DIR=c:/Program Files/Java/jre/axbridge
AXBRIDGE_UNIX_DIR=/cygdrive/c/Program\ Files/Java/jre/axbridge
AXBRIDGE_CLS_ID={D8244185-AE3C-19D6-ABF5-00B0D07B8582}
AXBRIDGE_PACKAGER=$(JAVADIR)/bin/packager.exe

DUBUILD=$(MS_SDK_BIN_DIR)/dubuild

SIGNCODE=$(MS_SDK_BIN_DIR)/signcode 

SIGNCODE_SIGNING_FLAGS=-v $(MS_PVK) -spc $(MS_SPC)\
	-j javasign.dll -jp LOW

SIGNCODE_TIMESTAMP_FLAGS=-x -t\
	http://timestamp.verisign.com/scripts/timestamp.dll -tr 5

JARSIGNER_FLAGS=-keystore \
../../java_dependencies/certs/code-signing-cert-thawte-2011-05-09.p12 \
-storetype "pkcs12"

JARSIGNER_ALIAS="Hush Communications Canada, Inc. Code Signing Certificate"

JVC_FLAGS=/g- /O /cp:p $(CLASSPATH) /nologo /w1 /x /d ../build
JVC_DEBUG_FLAGS=/g /cp:p $(CLASSPATH) /nologo /w1 /x /d ../build
JAVAC_FLAGS=-g:none -O -classpath $(CLASSPATH) -nowarn -d build -source 1.2 -target 1.1
JAVAC_DEBUG_FLAGS=-g -classpath $(CLASSPATH) -d build -source 1.5 -target 1.5

CAB=HushEncryptionEngine.cab
SUN_JAR=HushEncryptionEngine.jar
FULL_JAR=HushEncryptionEngine_$(VERSION1)-$(VERSION2)-$(VERSION3)-$(VERSION4).jar
AXBRIDGE_JAR=HushEncryptionEngineAxbridge.jar
DLL=HushEncryptionEngineAxbridge.dll

SRC=com/hush/core/security/applet/HushEncryptionEngine.java \
	com/hush/core/security/applet/HushEncryptionEngineBeanInfo.java \
	com/hush/hee/HushEncryptionEngineCoreBeanInfo.java \
	org/bouncycastle/crypto/engines/AESEngine.java \
	org/bouncycastle/crypto/digests/SHA1Digest.java
	
EXT_SRC=org/bouncycastle/crypto/engines/TwofishEngine.java \
	org/bouncycastle/crypto/engines/DESedeEngine.java \
	org/bouncycastle/crypto/engines/CAST5Engine.java \
	org/bouncycastle/crypto/engines/IDEAEngine.java \
	org/bouncycastle/crypto/digests/MD5Digest.java \
	org/bouncycastle/crypto/digests/RIPEMD160Digest.java \
	org/bouncycastle/crypto/digests/SHA256Digest.java \
	org/bouncycastle/crypto/digests/SHA384Digest.java \
	org/bouncycastle/crypto/digests/SHA512Digest.java \
	com/hush/hee/legacy/LegacyBlowfishEngine.java \
	com/hush/hee/legacy/LegacyHushmail.java

MSIE_SRC=com/hush/applet/security/MicrosoftStrategy.java

SUN_SRC=com/hush/applet/security/SunStrategy.java

FULL_SRC=com/hush/util/CommonsLoggerDelegate.java

AXBRIDGE_SRC=org/bouncycastle/crypto/engines/AESEngine.java \
	org/bouncycastle/crypto/digests/SHA1Digest.java \
	com/hush/hee/axbridge/HushEncryptionEngineAxbridge.java


#ALGORITHM_TEST_SRC=com/hush/hee/AlgorithmTests.java
ALGORITHM_TEST_SRC=

cab:
	if [ -d src11 ]; then rm -fr src11; fi
	mkdir src11
	cp -R com org src11
	find src11 -name "*.java.1.1" -exec sh -c 'cp {} `echo {} | sed s/.1.1$$//`' \;
	if [ -d build ]; then rm -fr build; fi
	#find com org -name "*.class" -exec rm -f {} \;
	mkdir build
	cd src11;$(JVC) $(JVC_FLAGS) $(SRC) $(MSIE_SRC) $(EXT_SRC) $(ALGORITHM_TEST_SRC)
	cd build;$(JAR) -Mcvf $(TMP_JAR_1) .
	$(PROGUARD) -printmapping $(CAB)_map.txt -libraryjars ..\\java_dependencies\\lib\\microsoft.jar
	cd build;rm -fr com org;$(JAR) -xvf $(TMP_JAR_2)
	cd build;$(DUBUILD) ../dist/$(CAB) . /D "HushEncryptionEngine3a"\
	  /N "HushEncryptionEngine3a" /I *.class\
	  /V "$(VERSION1),$(VERSION2),$(VERSION3),$(VERSION4)"
	cd build;$(SIGNCODE) $(SIGNCODE_SIGNING_FLAGS) ../dist/$(CAB)
	cd build;$(SIGNCODE) $(SIGNCODE_TIMESTAMP_FLAGS) ../dist/$(CAB)
	rm -fr build
	rm -fr src11

sunjar:
	if [ -d build ]; then rm -fr build; fi
	#find com org -name "*.class" -exec rm -f {} \;
	mkdir build
	$(JAVAC) $(JAVAC_FLAGS) $(SRC) $(SUN_SRC) $(EXT_SRC) $(ALGORITHM_TEST_SRC)
	cd build;$(JAR) -Mcvf $(TMP_JAR_1) .
	$(PROGUARD) -printmapping $(SUN_JAR)_map.txt -libraryjars "'$(WINJAVADIR)/jre/lib/rt.jar'(java/**.class):'../java_dependencies/lib/netscape.jar'(netscape/javascript/**.class)"
	cd build;rm -fr com org;$(JAR) -xvf $(TMP_JAR_2)
	cd build;rm -fr $(TMP_JAR_1) $(TMP_JAR_2)
	cd build;$(JAR) -cvf $(SUN_JAR) .
	cd build;$(JARSIGNER) $(JARSIGNER_FLAGS) $(SUN_JAR) $(JARSIGNER_ALIAS)
	mv build/$(SUN_JAR) dist/
	rm -fr build

fulljar:
	if [ -d build ]; then rm -fr build; fi
	#find com org -name "*.class" -exec rm -f {} \;
	mkdir build
	$(JAVAC) $(JAVAC_DEBUG_FLAGS) $(SRC) $(SUN_SRC) $(EXT_SRC) $(FULL_SRC) $(ALGORITHM_TEST_SRC)
	cd build;$(JAR) -cvf $(FULL_JAR) .
	cd build;$(JARSIGNER) $(JARSIGNER_FLAGS) $(FULL_JAR) $(JARSIGNER_ALIAS)
	mv build/$(FULL_JAR) dist/
	rm -fr build

prepdll:
	if [ -d src11 ]; then rm -fr src11; fi
	mkdir src11
	cp -R com org src11
	find src11 -name "*.java.1.1" -exec sh -c 'cp {} `echo {} | sed s/.1.1$$//`' \;
	find src11 -type d -name ".svn" | xargs rm -fr

axbridgejar:
	if [ -d build ]; then rm -fr build; fi
	rm -f dist/$(AXBRIDGE_JAR)
	mkdir build
	$(JAVAC) $(JAVAC_DEBUG_FLAGS) $(SRC) $(SUN_SRC) $(EXT_SRC) $(AXBRIDGE_SRC) $(ALGORITHM_TEST_SRC)
	cd build;$(JAR) -cvf $(AXBRIDGE_JAR) .
	mv build/$(AXBRIDGE_JAR) dist/
	rm -fr build

axbridgedll: axbridgejar
	rm -f dist/${DLL}
	if [ ! -d $(AXBRIDGE_UNIX_DIR) ]; then mkdir $(AXBRIDGE_UNIX_DIR); fi
	if [ ! -d $(AXBRIDGE_UNIX_DIR)/bin ]; then mkdir $(AXBRIDGE_UNIX_DIR)/bin; fi
	rm -fv $(AXBRIDGE_UNIX_DIR)/lib/$(AXBRIDGE_JAR)
	$(AXBRIDGE_PACKAGER) -clsid $(AXBRIDGE_CLS_ID) -out dist \
		dist\\$(AXBRIDGE_JAR) com.hush.hee.axbridge.HushEncryptionEngineAxbridge

axbridgereg: axbridgejar
	rm -f dist/${DLL}
	if [ ! -d $(AXBRIDGE_UNIX_DIR) ]; then mkdir $(AXBRIDGE_UNIX_DIR); fi
	if [ ! -d $(AXBRIDGE_UNIX_DIR)/bin ]; then mkdir $(AXBRIDGE_UNIX_DIR)/bin; fi
	rm -fv $(AXBRIDGE_UNIX_DIR)/lib/$(AXBRIDGE_JAR)
	$(AXBRIDGE_PACKAGER) -clsid $(AXBRIDGE_CLS_ID) -out "$(AXBRIDGE_DIR)/bin" \
		-reg dist\\$(AXBRIDGE_JAR) com.hush.hee.axbridge.HushEncryptionEngineAxbridge

javadoc:
	if [ -d javadoc ]; then rm -fr javadoc; fi
	mkdir javadoc
	$(JAVADOC) -classpath $(CLASSPATH) -d javadoc -public\
		-windowtitle "Hush Java API" @packages

pkg: javadoc
	find com org -name "*.class" -exec rm -f {} \;
	mkdir pkg
	mkdir pkg/src
	cp -R com pkg/src/
	rm -frv pkg/src/com/hush/test/hee
	rm -frv pkg/src/com/hush/hee/core
	mkdir pkg/javascript
	cp ../shared/javascript/printApplet.js pkg/javascript/
	cp -R javadoc pgptest pkg/
	mkdir pkg/applets
	cp dist/$(SUN_JAR) pkg/applets
	cp dist/$(FULL_JAR) pkg
	cp HushOpenPGPDeveloperGuide.html HushEncryptionEngineDeveloperGuide.html \
	changelog.txt pkg/
	mkdir pkg/verification
	cp Makefile proguard.conf verification.txt pkg/verification
	cp LICENSING.txt pkg
	cd pkg;zip -r \
	../dist/HushEncryptionEngine_$(VERSION1)-$(VERSION2)-$(VERSION3)-$(VERSION4).zip \
	*
	rm -fr pkg
	
	
