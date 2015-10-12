
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

public class ClientApp
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
		try
		{
			String fileName = "salt" + username + ".txt";
			FileReader fileReader = new FileReader(fileName);
			BufferedReader buff = new BufferedReader(fileReader);
			String line = null;
			while((line = buff.readLine()) != null)
				_pwd += line;
			buff.close();  
		}
        catch(FileNotFoundException ex) 
		{
            System.out.println("No Salt in Use");                
        }
        catch(IOException ex) 
		{
            System.out.println("Error Importing Salt");                   
        }
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
		
		if(username.equals(_pwd))
		{
			System.out.print("First Time Login ---> Password Reset Required. ");
			System.out.print("What's your new Password? : ");
			_pwd = new String(System.console().readPassword());
			cp();
		}
		
		long curtime = (new Date()).getTime()/1000;
		while(true)
		{
			if((new Date()).getTime()/1000 - curtime > 10)
			{
				try
				{
					String sourceFile = fileClient.getInsecureFile(groupClient.getToken(username, pwd));
					if(sourceFile != "")
					{
						sourceFile = sourceFile.substring(1);
						String groupname;
						Envelope env;
						if((groupname = fileClient.getFileGroup(sourceFile, groupClient.getToken(username, pwd))) != null)
							if((env = groupClient.getFileCryptoInfo(groupname, groupClient.getToken(username, pwd), sourceFile, false)) != null)
								if(fileClient.download(sourceFile, "temp.txt", env, groupClient.getToken(username, pwd)))
									if(fileClient.delete(sourceFile, groupClient.getToken(username, pwd)))
										if((env = groupClient.getFileCryptoInfo(groupname, groupClient.getToken(username, pwd), sourceFile, true)) != null)
											if(fileClient.upload("temp.txt", "/" + sourceFile, env, groupname, groupClient.getToken(username, pwd)))
												if(new File("temp.txt").delete())
												{
													System.out.println("\n************ The file " + sourceFile + " has been re-encrypted ************\n");
													curtime = (new Date()).getTime()/1000;
												}
					}
				}
				catch(Exception exception)
				{
					System.err.println("Error: Failed to complete command.\n" + exception.getMessage());
					exception.printStackTrace(System.err);
				}		
			}
			System.out.print("Enter \"help\" for a list of commands: ");
			String command = userInput.readLine().trim().toUpperCase();
			
			if(command.equals("HELP"))
			{
				 
				System.out.println("\n################################################################################################################################################\n");
				
				System.out.println("List of commands:");
				System.out.println("----------------");
				
				System.out.println("lf   : List all files you have access to.");
				System.out.println("df   : Delete file shared in group.");
				System.out.println("up   : Upload a file to share with a group.");
				System.out.println("down : Download a file you have access to.");
				
				System.out.println("lm   : List members of an owned group. | Owner only.");
				System.out.println("cp   : Change Password.");
				System.out.println("cu   : Create a new user. | Admin only.");
				System.out.println("du   : Delete a user. | Admin only.");
				System.out.println("cg   : Create a new group.");
				System.out.println("dg   : Delete a group. | Owner only.");
				System.out.println("ug   : Add a user to an existing group. | Owner only.");
				System.out.println("gu   : Remove a user from group. | Owner only.");
				
				System.out.println("exit : exit the file server.");
				
				System.out.println("\n################################################################################################################################################\n");
			}
			else if(command.equals("LF"))
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
			else if(command.equals("DF"))
			{
				 
				try
				{
					System.out.print("Enter the name of file you want to delete: ");
					String fileToBeDeleted = userInput.readLine();
					if(fileClient.delete(fileToBeDeleted, groupClient.getToken(username, pwd)))
						System.out.println("\n************ The file " + fileToBeDeleted + " has been deleted successfully ************\n");
					else System.out.println("\n###### Failed to delete the file " + fileToBeDeleted + " ######\n");
				}
				catch(Exception exception)
				{
					System.err.println("Error: Failed to complete command.\n" + exception.getMessage());
					exception.printStackTrace(System.err);
				}
			}
			else if(command.equals("UP"))
			{	
				 
				try
				{
					System.out.print("What's the name of the file that you want to upload? : ");
					String sourceFile = userInput.readLine();
					System.out.print("How do you want to name it within the shared database? : ");
					String fileDestination = userInput.readLine();
					System.out.print("Which group do you want to share this file with? : ");
					String groupname = userInput.readLine();
					Envelope env = null;
					boolean success = false;
					if((env = groupClient.getFileCryptoInfo(groupname, groupClient.getToken(username, pwd), fileDestination, true)) != null)
						if((success = fileClient.upload(sourceFile, "/" + fileDestination, env, groupname, groupClient.getToken(username, pwd))) == true)
							System.out.println("\n************ The file " + sourceFile + " has been uploaded successfully ************\n");
					if(!success)
						System.out.println("\n###### Failed to upload the file " + sourceFile + " ######\n");
				}
				catch(Exception exception)
				{
					System.err.println("Error: Failed to complete command.\n" + exception.getMessage());
					exception.printStackTrace(System.err);
				}
			}
			else if(command.equals("DOWN"))
			{
				 
				try
				{
					System.out.print("What's the name of the file you want to download from the shared database? : ");
					String sourceFile = userInput.readLine();
					System.out.print("How do you want to name it within your local directory? : ");
					String fileDestination = userInput.readLine();
					String groupname = null;
					Envelope env = null;
					boolean success = false;
					if((groupname = fileClient.getFileGroup(sourceFile, groupClient.getToken(username, pwd))) != null)
						if((env = groupClient.getFileCryptoInfo(groupname, groupClient.getToken(username, pwd), sourceFile, false)) != null)
							if((success = fileClient.download(sourceFile, fileDestination, env, groupClient.getToken(username, pwd))) == true)
								System.out.println("\n************ The file " + sourceFile + " has been downloaded successfully ************\n");
					if(!success)
						System.out.println("\n###### Failed to download the file " + sourceFile + " ######\n");
				}
				catch(Exception exception)
				{
					System.err.println("Error: Failed to complete command.\n" + exception.getMessage());
					exception.printStackTrace(System.err);
				}
			}
			else if(command.equals("LM"))
			{
				 
				try
				{
					System.out.print("What's the group name? : ");
					String groupname = userInput.readLine().trim();
					ArrayList<String> nameList = groupClient.listMembers(groupname, groupClient.getToken(username, pwd));
					System.out.println("\n************************** Start Listing **************************\n");
					if(nameList != null)
					{
						for(String name : nameList)
							System.out.println(name);
						System.out.println("\n************************** Listing Completed **************************\n");
					}
					else System.out.println("\n###### Listing Failed ######\n");
				}
				catch(Exception exception)
				{
					System.err.println("Error: Failed to complete command.\n" + exception.getMessage());
					exception.printStackTrace(System.err);
				}
			}
			else if(command.equals("CP"))
			{
				 
				cp();
			}
			else if(command.equals("CU"))
			{
				 
				try
				{
					System.out.print("What's the user name? : ");
					String newUserID = userInput.readLine().trim();
					SHA256_digest.update(newUserID.getBytes("UTF-8"));
					if(groupClient.createUser(newUserID, SHA256_digest.digest(), groupClient.getToken(username, pwd)))
						System.out.println("\n************ The user " + newUserID + " has been created successfully ************\n");
					else
						System.out.println("\n###### Failed to create the user " + newUserID + " ######\n");
				}
				catch(Exception exception)
				{
					System.err.println("Error: Failed to complete command.\n" + exception.getMessage());
					exception.printStackTrace(System.err);
				}
			}
			else if(command.equals("DU"))
			{
				 
				try
				{
					System.out.print("What's the user name? : ");
					String userToBeDeleted = userInput.readLine().trim();
					if(groupClient.deleteUser(userToBeDeleted, groupClient.getToken(username, pwd)))
						System.out.println("\n************ The user " + userToBeDeleted + " has been deleted successfully ************\n");
					else
						System.out.println("\n###### Failed to delete the user " + userToBeDeleted + " ######\n");
				}
				catch(Exception exception)
				{
					System.err.println("Error: Failed to complete command.\n" + exception.getMessage());
					exception.printStackTrace(System.err);
				}
			}
			else if(command.equals("CG"))
			{
				 
				try
				{
					System.out.print("What's the group name? : ");
					String newgroupname = userInput.readLine().trim();
					if(groupClient.createGroup(newgroupname, groupClient.getToken(username, pwd)))
						System.out.println("\n************ The group " + newgroupname + " has been created successfully ************\n");
					else
						System.out.println("\n###### Failed to create the group " + newgroupname + " ######\n");
				}
				catch(Exception exception)
				{
					System.err.println("Error: Failed to complete command.\n" + exception.getMessage());
					exception.printStackTrace(System.err);
				}
			}
			else if(command.equals("DG"))
			{
				 
				try
				{
					System.out.print("What's the group name? : ");
					String delgroupname = userInput.readLine().trim();
					
					if(groupClient.deleteGroup(delgroupname, groupClient.getToken(username, pwd)))
					{
							System.out.println("\n************ The group " + delgroupname + " has been deleted successfully ************\n");
							if(fileClient.deleteAssociatedFiles(delgroupname, groupClient.getToken(username, pwd)))
								System.out.println("\n************ All files associated with the group " + delgroupname + " have been deleted successfully ************\n");
							else System.out.println("\n###### Failed to delete all files associated with the group " + delgroupname + " ######\n");					
					}
					else System.out.println("\n###### Failed to delete the group " + delgroupname + " ######\n");
				}
				catch(Exception exception)
				{
					System.err.println("Error: Failed to complete command.\n" + exception.getMessage());
					exception.printStackTrace(System.err);
				}
			}
			
			else if(command.equals("UG"))
			{
				 
				try
				{
					System.out.print("What's the user name? : ");
					String userToBeAdded = userInput.readLine().trim();
					System.out.print("What's the group name? : ");
					String groupname = userInput.readLine().trim();
					if(groupClient.addUserToGroup(userToBeAdded, groupname, groupClient.getToken(username, pwd)))
						System.out.println("\n************ The user " + userToBeAdded + " has been added to the group " + groupname + " successfully ************\n");
					else
						System.out.println("\n###### Failed to add the user " + userToBeAdded + " to the group " + groupname + " ######\n");
				}
				catch(Exception exception)
				{
					System.err.println("Error: Failed to complete command.\n" + exception.getMessage());
					exception.printStackTrace(System.err);
				}
			}
			else if(command.equals("GU"))
			{
				 
				try
				{
					System.out.print("What's the user name? : ");
					String userToBeDeletedName = userInput.readLine().trim();
					System.out.print("What's the group name? : ");
					String groupname = userInput.readLine().trim();
					if(groupClient.deleteUserFromGroup(userToBeDeletedName, groupname, groupClient.getToken(username, pwd)))
						System.out.println("\n************ The user " + userToBeDeletedName + " has been deleted from the group " + groupname + " successfully ************\n");
					else
						System.out.println("\n###### Failed to delete the user " + userToBeDeletedName + " from the group " + groupname + " ######\n");						
				}
				catch(Exception exception)
				{
					System.err.println("Error: Failed to complete command.\n" + exception.getMessage());
					exception.printStackTrace(System.err);
				}
			}
			else if(command.equals("EXIT"))
			{
				cp();
				fileClient.disconnect();
				groupClient.disconnect();
				break;
			}
			else System.out.println("\n\n$$$$$$$$$$$$$$$$$$$$$$$ ----------- Unknown Command ----------- $$$$$$$$$$$$$$$$$$$$$$$\n");
		}
		
	}
	
	public static void cp()
	{
		try
		{
			String fileName = "salt" + username + ".txt";
			FileWriter fileWriter = new FileWriter(fileName, false);
			BufferedWriter bufferedWriter = new BufferedWriter(fileWriter);
			String salt = new BigInteger(256, random).toString(32);
			bufferedWriter.write(salt);
			bufferedWriter.newLine();
			bufferedWriter.close();
			SHA256_digest.update((_pwd + salt).getBytes("UTF-8"));
			byte[] newPwd = SHA256_digest.digest();
			if(groupClient.changePwd(username, newPwd, groupClient.getToken(username, pwd)))
			{
				System.out.println("\n************ New Salt in Use ************\n");
				pwd = newPwd;
			}
			else
				System.out.println("\n###### Salt Reset Failed ######\n");
		}
		catch(Exception exception)
		{
			System.err.println("Error: Failed to complete command.\n" + exception.getMessage());
			exception.printStackTrace(System.err);
		}
	}
}