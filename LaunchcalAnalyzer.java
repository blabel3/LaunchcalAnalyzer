import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;

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
					System.out.println("uses-permission\t"+permission+"\t"+protectionLevel);
				}
				for(String permission : appManifest.definedPermissionsMap.keySet()) {
					System.out.println("permission\t"+permission+"\t"+appManifest.definedPermissionsMap.get(permission).protectionLevel);
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
