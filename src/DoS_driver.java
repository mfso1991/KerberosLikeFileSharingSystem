
/*
 *	Author : You Zhou
 */

import java.util.*;
import java.io.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.math.*;

public class DoS_driver
{
	private static UserToken userToken;
	private static SecureRandom random = new SecureRandom();
	private static KeyGenerator AES_keyGenerator = null;
	private static MessageDigest SHA256_digest = null;
	private static String username = null;
	private static String _pwd = null;
	private static byte[] pwd = null;
	private static GroupClient groupClient = null;
	private static FileClient fileClient = null;
	
	public static void main(String[] args) throws Exception
	{		
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		BufferedReader userInput = new BufferedReader(new InputStreamReader(System.in));
		
		System.out.print("Enter the name of the group server: ");
		String groupServer = userInput.readLine();
		System.out.print("Enter the port of the group server: ");
		int groupPort = Integer.parseInt(userInput.readLine());
		groupClient = new GroupClient();
		if(!groupClient.connect(groupServer, groupPort))
		{
			System.out.println("###### GroupServer Connection Failed ######");
			System.exit(0);
		}
		System.out.println("\n*** You are now connected to the group server " + groupServer + " : " + groupPort + " ***\n");
		
		System.out.print("Enter the name of the file server: ");
		String fileServer = userInput.readLine();
		System.out.print("Enter the port of the file server: ");
		int filePort = Integer.parseInt(userInput.readLine());
		fileClient = new FileClient();
		if(!fileClient.connect(fileServer, filePort))
		{
			System.out.println("###### FileServer Connection Failed ######");
			System.exit(0);
		}
		System.out.println("\n*** You are now connected to the file server " + fileServer + " : " + filePort + " ***\n");
		
		System.out.print("Please enter your user name: ");
		username = userInput.readLine();
		System.out.print("Please enter your password: ");
		_pwd = new String(System.console().readPassword());
		SHA256_digest = MessageDigest.getInstance("SHA256");
		SHA256_digest.update(_pwd.getBytes("UTF-8"));
		pwd = SHA256_digest.digest();
		
		AES_keyGenerator = KeyGenerator.getInstance("AES");
		AES_keyGenerator.init(128);
		
		System.out.println("\n************ Client-GroupServer Handshaking ************");
		if(!groupClient.handShaking(new BigInteger(512, random).toString(64).getBytes("UTF-8"), AES_keyGenerator.generateKey(), fileClient.fetchPublicKey(), username, pwd))
		{							
			System.out.println("###### Client-GroupServer HandShaking Failed ######");
			fileClient.disconnect();
			groupClient.disconnect();
			System.exit(0);
		}
		System.out.println("************ Client-GroupServer HandShaking Completed ************\n");

		System.out.println("\n************ Client-FileServer Handshaking ************");
		if(!fileClient.handShaking(new BigInteger(512, random).toString(64).getBytes("UTF-8"), AES_keyGenerator.generateKey(), groupClient.fetchPublicKey(), random.nextLong(), groupClient.getToken(username, pwd)))
		{
			System.out.println("###### Client-FileServer Handshaking Failed ######");
			System.exit(0);
		}
		System.out.println("************ Client-FileServer Handshaking Completed ************\n");

		while(true)
		{
			try
			{
				ArrayList<String> listOfFilesAccessible = fileClient.listFiles(groupClient.getToken(username, pwd));
				if(listOfFilesAccessible != null)
				{
					System.out.println("\n************************** Start Listing Files **************************\n");
					for(String fileAccessible : listOfFilesAccessible)
						System.out.println(fileAccessible);
					System.out.println("\n************************** Listing Files Completed **************************\n");	
				}
				else System.out.println("\n###### Listing Files Failed ######\n");
			}
			catch(Exception exception)
			{
				System.err.println("Error: Failed to complete command.\n" + exception.getMessage());
				exception.printStackTrace(System.err);
			}	
		}
	}
}