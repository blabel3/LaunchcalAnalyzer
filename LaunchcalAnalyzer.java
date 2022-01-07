import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;

import java.util.HashMap;
import java.util.Map;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

class LaunchcalAnalyzer {
	private static String APP_MANIFEST = "AndroidManifest.xml";
	private static String FRAMEWORK_MANIFEST = "FrameworksBaseCoreResAndroidManifest.xml";
	private static String DOWNLOADPROVIDER_MANIFEST = "PackagesProvidersDownloadProviderAndroidManifest.xml";
	
	public enum AndroidMbaPolicyPermissions {
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
		SHARED_UID("NO_PERMISSION_CHECK_UID", 
				"13.2.10 Shared System UIDs policy",
				"https://docs.partner.android.com/gms/policies/domains/mba?authuser=3#shared-system-uids-policy");
		public final String name;
		public final String policy;
		public final String link;

		AndroidMbaPolicyPermissions(String n, String p, String l) {
			this.name = n;
			this.policy = p;
			this.link = l;
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
		if(args.length < 1) {
			System.out.println("Usage: LaunchcalAnalyzer <PATH to Decoded apk>");
		}
		else {
			try {
				LaunchcalAnalyzer analyzer = new LaunchcalAnalyzer();
				AndroidManifest frameworkManifest = analyzer.populateAndroidPermissions(FRAMEWORK_MANIFEST);
			        System.out.println("Size of Framework Manifest permission declarations: "+frameworkManifest.definedPermissionsMap.size());
			        System.out.println("Size of Framework Manifest permission usages: "+frameworkManifest.usedPermissionsMap.size());
				AndroidManifest downloadProviderManifest = analyzer.populateAndroidPermissions(DOWNLOADPROVIDER_MANIFEST);
			        System.out.println("Size of Framework Manifest permission declarations: "+downloadProviderManifest.definedPermissionsMap.size());
			        System.out.println("Size of Framework Manifest permission usages: "+downloadProviderManifest.usedPermissionsMap.size());

				File appDir = new File(args[0]);
				if(!appDir.isDirectory()) {
					throw new IOException("Input: "+args[0]+" is not a directory");
				}
				String path = appDir.getAbsolutePath();
				System.out.println("Analyzing permissions in : "+path+"/"+APP_MANIFEST);
				BufferedReader reader = new BufferedReader(new FileReader(path+"/"+APP_MANIFEST));
				AndroidManifest appManifest = analyzer.populateAndroidPermissions(path+"/"+APP_MANIFEST);
				System.out.println("Details for package: "+appManifest.packageName);
				System.out.println("\tShared Uid? : "+appManifest.sharedUid);
				System.out.println("\nUsage type\tPermission Name\tDefined ProtectionLevel");

				//Loop through used permissions
				//Pull the protection level from known Manifests (Framework, app)
				for(String permission : appManifest.usedPermissionsMap.keySet()) {
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
					System.out.println(String.format("uses-permission\t%-80s\t%-10s",permission,protectionLevel));
				}

				//Print out the defined permissions
				// - Maybe do some checking for trailing spaces (same as Asset)?
				for(String permission : appManifest.definedPermissionsMap.keySet()) {
					System.out.println(String.format("permission\t%-80s\t%-10s",permission,appManifest.definedPermissionsMap.get(permission).protectionLevel));
				}

				//Loop again through used permissions and flag any concerns for followup
				//MBA POLICY
				System.out.println("\n\nMBA Policy concerns:");
				for(String permission : appManifest.usedPermissionsMap.keySet()) {
					String mbaConcern = "";
					for(AndroidMbaPolicyPermissions mba : AndroidMbaPolicyPermissions.values()) {
						if(permission.equals(mba.name)) {
							System.out.println("uses-permission\t"+permission);
							System.out.println("\t"+mba.policy);
							System.out.println("\t"+mba.link);
						}
					}
				}
				//shared UID - 13.2.10
				//https://docs.partner.android.com/gms/policies/domains/mba?authuser=3#shared-system-uids-policy
				//Covers all UIDs defined in Process.java:
				//Values in 1xxx and Shell 2000
				if(appManifest.sharedUid != null) {
					System.out.println("App sharedUid value: "+appManifest.sharedUid);		
					System.out.println("\tCheck: ");
					System.out.println("\t"+AndroidMbaPolicyPermissions.SHARED_UID.policy);
					System.out.println("\t"+AndroidMbaPolicyPermissions.SHARED_UID.link);
				}

				//targetSdk value
				//https://docs.partner.android.com/gms/policies/domains/mba?authuser=3#mba-security-policies
				System.out.println("\ntargetSdk Check:");
				try {
					path = args[0].replace(" ", "\\ ")+"/apktool.yml";
					String[] cmd = {"sh", "-c", "grep -R 'targetSdk' "+path};
					Process p = Runtime.getRuntime().exec(cmd);
					reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
					String line;
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

				//apksign
				//https://docs.partner.android.com/gms/policies/domains/mba?authuser=3#jni-lib
				System.out.println("\napk Signage Check");
				try {
					path = args[0].replace(" ", "\\ ")+".apk";
					String[] cmd = {"sh", "-c", "/cygdrive/c/Android/AndroidSDK/build-tools/30.0.2/apksigner.bat verify -verbose -print-certs "+path};
					//System.out.println(cmd[2]);
					Process p = Runtime.getRuntime().exec(cmd);
					reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
					String line;
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
				System.out.println("\napk Compressed Libs Check");
				try {
					path = args[0].replace(" ", "\\ ")+".apk";
					String[] cmd = {"sh", "-c", "unzip -v "+path+" 'lib/*.so'"};
					//System.out.println(cmd[2]);
					Process p = Runtime.getRuntime().exec(cmd);
					reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
					String line;
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
			}
			catch (FileNotFoundException e) {
				System.out.println(e);
			}
			catch (IOException e) {
				System.out.println(e);
			}
		}
	}

	// Populate a list of Android-defined permissions.
	// This requires periodically downloading manifests from:
	// 	frameworks/base/core/res/AndroidManifest.xml
	// 	frameworks/base/core/res/AndroidManifest.xml
	public AndroidManifest populateAndroidPermissions(String manifestFileName) {
		try {
			SAXParserFactory factory = SAXParserFactory.newInstance();
			SAXParser saxParser = factory.newSAXParser();
			AndroidManifestXmlHandler handler = new AndroidManifestXmlHandler();
			saxParser.parse(manifestFileName, handler);
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
