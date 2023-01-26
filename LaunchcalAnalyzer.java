import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;

import java.util.HashMap;
import java.util.Map;
import java.util.logging.*;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

class LaunchcalAnalyzer {
	private static String currentOS = "Android S";
	private static String nextOS = "Android T";
	private static String APP_MANIFEST = "AndroidManifest.xml";
	private static String S_FRAMEWORK_MANIFEST = "S_FrameworksBaseCoreResAndroidManifest.xml";
	private static String S_DOWNLOADPROVIDER_MANIFEST = "S_PackagesProvidersDownloadProviderAndroidManifest.xml";
	private static String T_FRAMEWORK_MANIFEST = "T_FrameworksBaseCoreResAndroidManifest.xml";
	private static String T_DOWNLOADPROVIDER_MANIFEST = "T_PackagesProvidersDownloadProviderAndroidManifest.xml";
	public AndroidManifest frameworkManifestCurrent;
	public AndroidManifest downloadProviderManifestCurrent;
	public AndroidManifest frameworkManifestNext;
	public AndroidManifest downloadProviderManifestNext;

	static Logger logger = Logger.getLogger("com.motorola.launchcalanalyzer");

	static {
		System.setProperty("java.util.logging.SimpleFormatter.format", "[%1$tF %1$tT] %4$-7s: %5$s %n");
		logger.setLevel(Level.WARNING);
	}

	public LaunchcalAnalyzer() {
		ClassLoader classLoader = getClass().getClassLoader();
		File manifestFile = new File(classLoader.getResource(S_FRAMEWORK_MANIFEST).getFile());
		frameworkManifestCurrent = populateAndroidPermissions(manifestFile);
		logger.info("Size of Framework Manifest permission declarations: "+frameworkManifestCurrent.definedPermissionsMap.size());
		logger.info("Size of Framework Manifest permission usages: "+frameworkManifestCurrent.usedPermissionsMap.size());
		manifestFile = new File(classLoader.getResource(S_DOWNLOADPROVIDER_MANIFEST).getFile());
		downloadProviderManifestCurrent = populateAndroidPermissions(manifestFile);
		logger.info("Size of Framework Manifest permission declarations: "+downloadProviderManifestCurrent.definedPermissionsMap.size());
		logger.info("Size of Framework Manifest permission usages: "+downloadProviderManifestCurrent.usedPermissionsMap.size());

		manifestFile = new File(classLoader.getResource(T_FRAMEWORK_MANIFEST).getFile());
		frameworkManifestNext = populateAndroidPermissions(manifestFile);
		logger.info("Size of Framework Manifest permission declarations: "+frameworkManifestNext.definedPermissionsMap.size());
		logger.info("Size of Framework Manifest permission usages: "+frameworkManifestNext.usedPermissionsMap.size());
		manifestFile = new File(classLoader.getResource(T_DOWNLOADPROVIDER_MANIFEST).getFile());
		downloadProviderManifestNext = populateAndroidPermissions(manifestFile);
		logger.info("Size of Framework Manifest permission declarations: "+downloadProviderManifestNext.definedPermissionsMap.size());
		logger.info("Size of Framework Manifest permission usages: "+downloadProviderManifestNext.usedPermissionsMap.size());
	}

	public enum AndroidMbaPolicyPermissions {
		READ_CALL_LOG("android.permission.READ_CALL_LOG",
				"13.2.3 SMS and call log permissions policy",
				"https://docs.partner.android.com/gms/policies/domains/mba?authuser=3#sms-call-log",
				"GtsSmsCallLogTestCases"),
		WRITE_CALL_LOG("android.permission.WRITE_CALL_LOG",
				"13.2.3 SMS and call log permissions policy",
				"https://docs.partner.android.com/gms/policies/domains/mba?authuser=3#sms-call-log",
				"GtsSmsCallLogTestCases"),
		PROCESS_OUTGOING_CALLS("android.permission.PROCESS_OUTGOING_CALLS",
				"13.2.3 SMS and call log permissions policy",
				"https://docs.partner.android.com/gms/policies/domains/mba?authuser=3#sms-call-log",
				"GtsSmsCallLogTestCases"),
		READ_SMS("android.permission.READ_SMS",
				"13.2.3 SMS and call log permissions policy",
				"https://docs.partner.android.com/gms/policies/domains/mba?authuser=3#sms-call-log",
				"GtsSmsCallLogTestCases"),
		SEND_SMS("android.permission.SEND_SMS",
				"13.2.3 SMS and call log permissions policy",
				"https://docs.partner.android.com/gms/policies/domains/mba?authuser=3#sms-call-log",
				"GtsSmsCallLogTestCases"),
		WRITE_SMS("android.permission.WRITE_SMS",
				"13.2.3 SMS and call log permissions policy",
				"https://docs.partner.android.com/gms/policies/domains/mba?authuser=3#sms-call-log",
				"GtsSmsCallLogTestCases"),
		RECEIVE_SMS("android.permission.RECEIVE_SMS",
				"13.2.3 SMS and call log permissions policy",
				"https://docs.partner.android.com/gms/policies/domains/mba?authuser=3#sms-call-log",
				"GtsSmsCallLogTestCases"),
		RECEIVE_WAP_PUSH("android.permission.RECEIVE_WAP_PUSH",
				"13.2.3 SMS and call log permissions policy",
				"https://docs.partner.android.com/gms/policies/domains/mba?authuser=3#sms-call-log",
				"GtsSmsCallLogTestCases"),
		RECEIVE_MMS("android.permission.RECEIVE_MMS",
				"13.2.3 SMS and call log permissions policy",
				"https://docs.partner.android.com/gms/policies/domains/mba?authuser=3#sms-call-log",
				"GtsSmsCallLogTestCases"),
		ACCESS_NOTIFICATIONS("android.permission.ACCESS_NOTIFICATIONS", 
				"13.2.6.Notification access and notification listeners policy",
				"https://docs.partner.android.com/gms/policies/domains/mba?authuser=3#notification-access-and-notification-listeners-policy"),
		RETRIEVE_WINDOW_CONTENT("android.permission.RETRIEVE_WINDOW_CONTENT", 
				"Accessibility and UI automation policy",
				"https://docs.partner.android.com/gms/policies/domains/mba?authuser=3#accessibility-and-ui-automation-policy"),
		OBSERVE_APP_USAGE("android.permission.OBSERVE_APP_USAGE", 
				"13.2.8 App and network usage statistics policy",
				"https://docs.partner.android.com/gms/policies/domains/mba?authuser=3#app-and-network-usage-statistics-policy"),
		PACKAGE_USAGE_STATS("android.permission.PACKAGE_USAGE_STATS", 
				"13.2.8 App and network usage statistics policy",
				"https://docs.partner.android.com/gms/policies/domains/mba?authuser=3#app-and-network-usage-statistics-policy"),
		GET_APP_OPS_STATS("android.permission.GET_APP_OPS_STATS", 
				"13.2.8 App and network usage statistics policy",
				"https://docs.partner.android.com/gms/policies/domains/mba?authuser=3#app-and-network-usage-statistics-policy"),
		READ_NETWORK_USAGE_HISTORY("android.permission.READ_NETWORK_USAGE_HISTORY", 
				"13.2.8 App and network usage statistics policy",
				"https://docs.partner.android.com/gms/policies/domains/mba?authuser=3#app-and-network-usage-statistics-policy"),
		DUMP("android.permission.DUMP", 
				"13.2.8 App and network usage statistics policy",
				"https://docs.partner.android.com/gms/policies/domains/mba?authuser=3#app-and-network-usage-statistics-policy"),
		CHANGE_COMPONENT_ENABLED_STATE("android.permission.CHANGE_COMPONENT_ENABLED_STATE", 
				"13.2.9 Forced or keep enabled apps policy",
				"https://docs.partner.android.com/gms/policies/domains/mba?authuser=3#forced-or-keep-enabled-apps-policy"),
		INSTALL_PACKAGES("android.permission.INSTALL_PACKAGES", 
				"13.3.3 App installation policy",
				"https://docs.partner.android.com/gms/policies/domains/mba?authuser=3#package-downloader-installer"),
		REQUEST_INSTALL_PACKAGES("android.permission.REQUEST_INSTALL_PACKAGES", 
				"Check bz/229232652",
				"https://support.google.com/googleplay/android-developer/answer/11899428#install_package_preview"),
		READ_LOGS("android.permission.READ_LOGS", 
				"13.2.12 Device Logs access policy",
				"https://docs.partner.android.com/gms/policies/preview/mba#device-logs-access-policy and see internal doc: https://docs.google.com/document/d/1_iJRdsg5bo7ofJjWHUmDK2Osfs2Cj8P1pWqToiFLDAo/edit#heading=h.tpepte7hw9je"),
		SHARED_UID("NO_PERMISSION_CHECK_UID", 
				"13.2.10 Shared System UIDs policy",
				"https://docs.partner.android.com/gms/policies/domains/mba?authuser=3#shared-system-uids-policy");
		public final String name;
		public final String policy;
		public final String link;
		public final String impactedTest;

		AndroidMbaPolicyPermissions(String n, String p, String l) {
			this.name = n;
			this.policy = p;
			this.link = l;
			this.impactedTest = "";
		}
		AndroidMbaPolicyPermissions(String n, String p, String l, String t) {
			this.name = n;
			this.policy = p;
			this.link = l;
			this.impactedTest = t;
		}
	}

	public class AndroidManifest {
		public Map<String, Permission> definedPermissionsMap;
		public Map<String, Permission> usedPermissionsMap;
		public String packageName;
		public String sharedUid;

		public AndroidManifest() {
			definedPermissionsMap = new HashMap<String, Permission>();
			usedPermissionsMap = new HashMap<String, Permission>();
			packageName = "";
			sharedUid = "";
		}

	}

	public class Permission {
		public String name;
		public String protectionLevel;

		public Permission(String n, String l) {
			name = n;
			protectionLevel = l;
		}
	}

	//Taken from https://mkyong.com/java/how-to-read-xml-file-in-java-sax-parser/
	public class AndroidManifestXmlHandler extends DefaultHandler {
		private StringBuilder currentValue = new StringBuilder();
		private AndroidManifest manifestDetails = new AndroidManifest();

		public AndroidManifest getManifestDetails() {
			return manifestDetails;
		}

		@Override
		public void startDocument() {
			//System.out.println("Start Document");
		}

		@Override
		public void endDocument() {
			//System.out.println("End Document");
		}

		@Override
		public void startElement(
				String uri,
				String localName,
				String qName,
				Attributes attributes) {

			// reset the tag value
			currentValue.setLength(0);

			if (qName.equalsIgnoreCase("manifest")) {
				String name = attributes.getValue("package");
				manifestDetails.packageName = name;
				manifestDetails.sharedUid = attributes.getValue("android:sharedUserId");

			}

			if (qName.equalsIgnoreCase("permission")) {
				String name = attributes.getValue("android:name");
				String protectionLevel = attributes.getValue("android:protectionLevel");
				//System.out.println("Permission: "+name+" with protectionLevel"+protectionLevel);
				if(!manifestDetails.definedPermissionsMap.containsKey(name)) {
					manifestDetails.definedPermissionsMap.put(name, new Permission(name, protectionLevel));
				}
			}
			//Used Permissions
			if (qName.equalsIgnoreCase("uses-permission")) {
				String name = attributes.getValue("android:name");
				String protectionLevel = "";
				//System.out.println("Permission: "+name+" with protectionLevel"+protectionLevel);
				if(!manifestDetails.usedPermissionsMap.containsKey(name)) {
					manifestDetails.usedPermissionsMap.put(name, new Permission(name, protectionLevel));
				}
			}
				}

		@Override
		public void endElement(String uri,
				String localName,
				String qName) {

		}

		// http://www.saxproject.org/apidoc/org/xml/sax/ContentHandler.html#characters%28char%5B%5D,%20int,%20int%29
		// SAX parsers may return all contiguous character data in a single chunk,
		// or they may split it into several chunks
		@Override
		public void characters(char ch[], int start, int length) {

			// The characters() method can be called multiple times for a single text node.
			// Some values may missing if assign to a new string

			// avoid doing this
			// value = new String(ch, start, length);

			// better append it, works for single or multiple calls
			currentValue.append(ch, start, length);

		}
	}

	public static void main(String[] args) {
		boolean compareTwoApk = false;
		boolean usesForegroundService = false;
		String targetSdkVal = "";
		String apkVersionName = "";
		LaunchcalAnalyzer analyzer = new LaunchcalAnalyzer();

		if(args.length < 1) {
			System.out.println("Usage for New     apks: LaunchcalAnalyzer <PATH to New apk>");
			System.out.println("Usage for Updated apks: LaunchcalAnalyzer <PATH to New apk> <PATH to Existing apk>");
			//Run a comparison of S vs. T manifest - temporary!!!!
			/*System.out.println("The following is a comparison of the S manifest to T manifests - this can be disabled.");
			for(String s : analyzer.frameworkManifestCurrent.definedPermissionsMap.keySet()) {
				//System.out.println("\t"+s+"\t"+analyzer.frameworkManifestCurrent.definedPermissionsMap.get(s).protectionLevel);
				if(analyzer.frameworkManifestNext.definedPermissionsMap.containsKey(s)) {
					System.out.println("\t"+s+"\t"+analyzer.frameworkManifestNext.definedPermissionsMap.get(s).protectionLevel);
				}
			}*/


			return;
		}
		else if(args.length > 1) {
			compareTwoApk = true;
		}
		BufferedReader reader;
		String line;
		File newApk;
		File existingApk = null;
		newApk = analyzer.processApk(args[0]);
		if(compareTwoApk) {
			existingApk = analyzer.processApk(args[1]);
		}

		File manifestFile = new File(getApkPath(newApk)+File.separator+APP_MANIFEST);
		AndroidManifest appManifest = analyzer.populateAndroidPermissions(manifestFile);
		System.out.println("Details for package: "+appManifest.packageName);
		System.out.println("\tShared Uid? : "+appManifest.sharedUid);
		System.out.println(String.format("Usage type\t%-60s\t%-40s\t%-40s","Permission Name","Defined ProtectionLevel "+currentOS, "Defined ProtectionLevel "+nextOS));
		//System.out.println("\nUsage type\tPermission Name\tDefined ProtectionLevel "+currentOS+"\tDefined ProtectionLevel "+nextOS);

		//Loop through used permissions
		//Pull the protection level from known Manifests (Framework, app)
		System.out.println("{noformat}");
		for(String permission : appManifest.usedPermissionsMap.keySet()) {
			String protectionLevelCurrent = analyzer.findPermissionProtectionLevel(analyzer.frameworkManifestCurrent, analyzer.downloadProviderManifestCurrent, permission, appManifest);
			String protectionLevelNext = analyzer.findPermissionProtectionLevel(analyzer.frameworkManifestNext, analyzer.downloadProviderManifestNext, permission, appManifest);
			System.out.println(String.format("uses-permission\t%-60s\t%-40s\t%-40s",permission,protectionLevelCurrent, protectionLevelNext));
		}

		//Print out the defined permissions
		// - Maybe do some checking for trailing spaces (same as Asset)?
		for(String permission : appManifest.definedPermissionsMap.keySet()) {
			System.out.println(String.format("permission\t%-60s\t%-40s",permission,appManifest.definedPermissionsMap.get(permission).protectionLevel));
		}
		System.out.println("{noformat}");

		//Loop again through used permissions and flag any concerns for followup
		//MBA POLICY
		System.out.println("\n\n*MBA Policy concerns:*");
		for(String permission : appManifest.usedPermissionsMap.keySet()) {
			if(permission.contains("FOREGROUND_SERVICE")) {
				usesForegroundService = true;
			}
			for(AndroidMbaPolicyPermissions mba : AndroidMbaPolicyPermissions.values()) {
				if(permission.equals(mba.name)) {
					System.out.println("uses-permission\t"+permission);
					System.out.println("\t"+mba.policy);
					System.out.println("\t"+mba.link);
					if(!mba.impactedTest.isEmpty()) {
						System.out.println("\tCheck Google Compliance Test: "+mba.impactedTest);
					}
				}
			}
		}		
		//shared UID - 13.2.10
		//https://docs.partner.android.com/gms/policies/domains/mba?authuser=3#shared-system-uids-policy
		//Covers all UIDs defined in Process.java:
		//Values in 1xxx and Shell 2000
		System.out.println("\n*Shared UID check:* (https://docs.partner.android.com/gms/policies/domains/mba?authuser=3#shared-system-uids-policy)");
		if(appManifest.sharedUid != null) {
			System.out.println("App sharedUid value: "+appManifest.sharedUid);		
			System.out.println("\tCheck: ");
			System.out.println("\t"+AndroidMbaPolicyPermissions.SHARED_UID.policy);
			System.out.println("\t"+AndroidMbaPolicyPermissions.SHARED_UID.link);
		}

		//targetSdk value
		//https://docs.partner.android.com/gms/policies/domains/mba?authuser=3#mba-security-policies
		System.out.println("\n*targetSdk Check:* (https://docs.partner.android.com/gms/policies/domains/mba?authuser=3#mba-security-policies)");
		try {
			String[] cmd = {"sh", "-c", "grep -R 'targetSdk' "+getApkPath(newApk)+"/"+"apktool.yml"};
			Process p = Runtime.getRuntime().exec(cmd);
			reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
			while((line = reader.readLine()) != null) {
				targetSdkVal = line;
				System.out.println("targetSdk: "+targetSdkVal);

			}
			reader = new BufferedReader(new InputStreamReader(p.getErrorStream()));
			while((line = reader.readLine()) != null) {
				System.out.println("Error: "+line);
			}
		} catch (IOException e) {
			System.out.println(e);
		}

		//Loop through uses-permissions to check for FOREGROUND_SERVICE
		if(usesForegroundService) {
			System.out.println("\t_NOTE: app uses FOREGROUND_SERVICE so on Android S must target SDK 31!_");
			System.out.println("\tGoogle enforcement deadline is December 15, 2022");
		}

		//Pull target apk versionName
		System.out.println("\n*versionName Check:*");
		try {
			String[] cmd = {"sh", "-c", "grep -R 'versionName' "+getApkPath(newApk)+"/"+"apktool.yml"};
			Process p = Runtime.getRuntime().exec(cmd);
			reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
			while((line = reader.readLine()) != null) {
				apkVersionName = line;
				System.out.println(apkVersionName.trim());

			}
			reader = new BufferedReader(new InputStreamReader(p.getErrorStream()));
			while((line = reader.readLine()) != null) {
				System.out.println("Error: "+line);
			}
		} catch (IOException e) {
			System.out.println(e);
		}

		//apksign
		//https://docs.partner.android.com/gms/policies/domains/mba?authuser=3#jni-lib
		System.out.println("\n*apk Signage Check:* (https://docs.partner.android.com/gms/policies/domains/mba?authuser=3#jni-lib)");
		System.out.println("Signature, compressed libs and page align conformance checked via GtsJniUncompressHostTestCases results");
		try {
			String[] cmd = {"sh", "-c", "apksigner verify -verbose -print-certs "+newApk.getAbsolutePath()};
			//System.out.println(cmd[2]);
			Process p = Runtime.getRuntime().exec(cmd);
			reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
			while((line = reader.readLine()) != null) {
				if(line.contains("Verified using")) {
					System.out.println(line);
				}
			}
			reader = new BufferedReader(new InputStreamReader(p.getErrorStream()));
			while((line = reader.readLine()) != null) {
				System.out.println(line);
			}
		} catch (IOException e) {
			System.out.println(e);
		}

		//compressed libraries
		System.out.println("\n*apk Compressed Libs Check:* (https://docs.partner.android.com/gms/policies/domains/mba?authuser=3#jni-lib)");
		try {
			String[] cmd = {"sh", "-c", "unzip -v "+newApk.getAbsolutePath()+" 'lib/*.so'"};
			//System.out.println(cmd[2]);
			Process p = Runtime.getRuntime().exec(cmd);
			reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
			while((line = reader.readLine()) != null) {
				System.out.println(line);
			}
			reader = new BufferedReader(new InputStreamReader(p.getErrorStream()));
			while((line = reader.readLine()) != null) {
				System.out.println(line);
			}
		} catch (IOException e) {
			System.out.println(e);
		}

		//zipalign
		//https://developer.android.com/studio/command-line/zipalign#usage
		System.out.println("\n*apk Zip Alignment Check:* (https://developer.android.com/studio/command-line/zipalign#usage)");
		try {
			String[] cmd = {"sh", "-c", "zipalign -c -p -v 4 "+newApk.getAbsolutePath()+" |grep lib"};
			//System.out.println(cmd[2]);
			Process p = Runtime.getRuntime().exec(cmd);
			reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
			while((line = reader.readLine()) != null) {
				if(line.contains("BAD")) {
					System.out.println(line);
				}
			}
			reader = new BufferedReader(new InputStreamReader(p.getErrorStream()));
			while((line = reader.readLine()) != null) {
				System.out.println(line);
			}
		} catch (IOException e) {
			System.out.println(e);
		}

		System.out.println("");
		if(compareTwoApk && existingApk != null) {
			System.out.println("*Delta Review* between: "+newApk.getName()+" and "+existingApk.getName());
		}
		else {
			System.out.println("Details for: "+newApk.getName()); 
		}
		System.out.println("Details for package: "+appManifest.packageName);
		System.out.println("versionName: "+apkVersionName);
		System.out.println("targetSdk: "+targetSdkVal);
		System.out.println("Modified Permissions:");
		//Compare Delta
		if(compareTwoApk && existingApk != null) {
			File existingManifestFile = new File(getApkPath(existingApk)+File.separator+APP_MANIFEST);
			AndroidManifest existingAppManifest = analyzer.populateAndroidPermissions(existingManifestFile);
			boolean dangerousPermissions = false;
			boolean privilegedPermissions = false;


			//Loop through new uses-perm and find in existing
			System.out.println("{noformat}");
			System.out.println("ADDED Permissions:");
			boolean printColumn = true;
			for(String permission : appManifest.usedPermissionsMap.keySet()) {
				if(!existingAppManifest.usedPermissionsMap.containsKey(permission)) {
					String protectionLevelCurrent = analyzer.findPermissionProtectionLevel(analyzer.frameworkManifestCurrent, analyzer.downloadProviderManifestCurrent, permission, appManifest);
					String protectionLevelNext = analyzer.findPermissionProtectionLevel(analyzer.frameworkManifestNext, analyzer.downloadProviderManifestNext, permission, appManifest);
					if(printColumn) {
		                            System.out.println(String.format("Usage type\t%-60s\t%-40s\t%-40s","Permission Name","Defined ProtectionLevel "+currentOS, "Defined ProtectionLevel "+nextOS));
					    printColumn = false;
					}
					System.out.println(String.format("uses-permission\t%-60s\t%-40s\t%-40s",permission,protectionLevelCurrent, protectionLevelNext));
					if(protectionLevelCurrent.contains("dangerous")||protectionLevelNext.contains("dangerous")) {
						dangerousPermissions = true;
					}
					if(protectionLevelCurrent.contains("privileged")||protectionLevelNext.contains("privileged")) {
						privilegedPermissions = true;
					}
				}
			}
			//Loop through existing uses-perm and find in new 
			System.out.println("REMOVED Permissions:");
			printColumn = true;
			for(String permission : existingAppManifest.usedPermissionsMap.keySet()) {
				if(!appManifest.usedPermissionsMap.containsKey(permission)) {
					String protectionLevelCurrent = analyzer.findPermissionProtectionLevel(analyzer.frameworkManifestCurrent, analyzer.downloadProviderManifestCurrent, permission, appManifest);
					String protectionLevelNext = analyzer.findPermissionProtectionLevel(analyzer.frameworkManifestNext, analyzer.downloadProviderManifestNext, permission, appManifest);
					if(printColumn) {
		                            System.out.println(String.format("Usage type\t%-60s\t%-40s\t%-40s","Permission Name","Defined ProtectionLevel "+currentOS, "Defined ProtectionLevel "+nextOS));
					    printColumn = false;
					}
					System.out.println(String.format("uses-permission\t%-60s\t%-40s\t%-40s",permission,protectionLevelCurrent, protectionLevelNext));
					if(protectionLevelCurrent.contains("dangerous")||protectionLevelNext.contains("dangerous")) {
						dangerousPermissions = true;
					}
					if(protectionLevelCurrent.contains("privileged")||protectionLevelNext.contains("privileged")) {
						privilegedPermissions = true;
					}
				}
			}
			System.out.println("{noformat}");

			if(dangerousPermissions) {
				System.out.println("Note: Dangerous permissions modified - check for pre-grant requirements.");
				System.out.println("\tSee MBA 13.2.2 Pregrant permission policy for more details. (https://docs.partner.android.com/gms/policies/domains/mba?authuser=3#mba-pregrant-permissions)");
			}
			if(privilegedPermissions) {
				System.out.println("Note: Privilged permissions modified - modify privapp-permissions xml when integrating.");
			}
		}
	}

	public String findPermissionProtectionLevel(AndroidManifest frameworkManifest, AndroidManifest downloadProviderManifest, String permission, AndroidManifest appManifest) {
		String protectionLevel = "NOT FOUND";
		if(frameworkManifest.definedPermissionsMap.containsKey(permission)) {
			protectionLevel = frameworkManifest.definedPermissionsMap.get(permission).protectionLevel;
		}
		else if(downloadProviderManifest.definedPermissionsMap.containsKey(permission)) {
			protectionLevel = downloadProviderManifest.definedPermissionsMap.get(permission).protectionLevel;
		}
		else if(appManifest.definedPermissionsMap.containsKey(permission)) {
			protectionLevel = appManifest.definedPermissionsMap.get(permission).protectionLevel;
		}
		return protectionLevel;
	}

	public static String getApkPath(File apk) {
		return apk.getAbsolutePath().replace(".apk", "");
	}

	public File processApk(String apkName) {
		File apk = new File(apkName);
		if(!apk.isFile()) {
			System.err.println("Input: "+apkName+" is not a File");
			System.exit(1);
		}
		String existingApkPath = getApkPath(apk);
		File checkDir = new File(existingApkPath);
		if(checkDir.isDirectory()) {
			logger.info("APK folder "+checkDir.getName()+"/ present - apk already decoded!");
		}
		else {
			decodeApk(apk);
		}
		return apk;
	}


	public void decodeApk(File apk) {
		try {
			logger.info("Decoding: "+apk.getName());
			Process pD = new ProcessBuilder("apktool", "d", apk.getAbsolutePath(), "-o", getApkPath(apk)).redirectError(ProcessBuilder.Redirect.INHERIT).start();
			pD.waitFor();
		}
		catch (IOException e) {
			System.err.println(e);
		}
		catch (InterruptedException e) {
			System.err.println(e);
		}
	}

	// Populate a list of Android-defined permissions.
	// This requires periodically downloading manifests from:
	// 	frameworks/base/core/res/AndroidManifest.xml
	// 	frameworks/base/core/res/AndroidManifest.xml
	public AndroidManifest populateAndroidPermissions(File manifestFile) {
		try {
			SAXParserFactory factory = SAXParserFactory.newInstance();
			SAXParser saxParser = factory.newSAXParser();
			AndroidManifestXmlHandler handler = new AndroidManifestXmlHandler();
			saxParser.parse(manifestFile, handler);
			return handler.getManifestDetails();

		}
		catch (FileNotFoundException e) {
			System.out.println(e);
		}
		catch (ParserConfigurationException | SAXException | IOException e) {
			System.out.println(e);
		}
		return null;
	}
}
