
/*
 *	An UserToken object uniquely defines an user in the system.
 *	
 */

import java.util.*;
import java.security.*;

public class UserToken implements java.io.Serializable
{
	private static final long serialVersionUID = -6699986336399821598L;;
	private String UserID = null;
	private ArrayList<String> groupsAccessibleToUser = new ArrayList<String>();
	private ArrayList<String> ownedGroups = new ArrayList<String>();
	private byte[] sig1 = null; //Will hold the RSA-SHA256 value of (group information = groupsAccessibleToUser to String + ownedGroups to String).
	private byte[] sig2 = null; //Will hold the RSA-SHA256 value of the public key (in byte[]) of the file server this UserToken is binding with.  

	public UserToken(String username)
	{
		UserID = username;
	}
	
	//Deep copy is needed during transmission, since otherwise the ouput stream might cache out the UserToken.
	public UserToken(UserToken oldToken) 
	{
		UserID = oldToken.UserID;
		groupsAccessibleToUser.addAll(oldToken.getUserAccessibleGroups());
		ownedGroups.addAll(oldToken.getGroupsOwnedByUser());
		sig1 = oldToken.sig1;
		sig2 = oldToken.sig2;
	}
	
	public String getUserID()
	{
		return UserID;
	}
	
	public ArrayList<String> getUserAccessibleGroups()
	{
		return new ArrayList<String>(groupsAccessibleToUser);
	}
	
	public ArrayList<String> getGroupsOwnedByUser()
	{
		return new ArrayList<String>(ownedGroups);
	}
	
	public void addOwnership(String groupname)
	{
		ownedGroups.add(groupname);
	}
	
	public void addMembership(String groupname)
	{
		groupsAccessibleToUser.add(groupname);
	}
	
	public boolean checkMembership(String groupname)
	{
		return groupsAccessibleToUser.contains(groupname);
	}
	
	public boolean checkOwnership(String groupname)
	{
		return ownedGroups.contains(groupname);
	}
	
	public void deAccess(String groupname)
	{
		removeMembership(groupname);
		if(checkOwnership(groupname))
			removeOwnership(groupname);
	}
	
	public void removeMembership(String groupname)
	{
		groupsAccessibleToUser.remove(groupname);
	}
	
	public void removeOwnership(String groupname)
	{
		ownedGroups.remove(groupname);
	}

	public byte[] extractTokenInfo()
	{
		return (groupsAccessibleToUser.toString() + ownedGroups.toString()).getBytes();
	}
	
	public void setSIG1(PrivateKey groupServer_privateKey)
	{
		try
		{
			Signature signer = Signature.getInstance("SHA256withRSA");
			signer.initSign(groupServer_privateKey);
			signer.update(this.extractTokenInfo());
			sig1 = signer.sign();
		}
		catch(Exception exception) 
		{
			System.out.println("Error: " + exception.getMessage());
			exception.printStackTrace();
		}
	}
	
	public boolean auth_SIG1(PublicKey groupServer_publicKey)
	{
		try
		{
			Signature verifier = Signature.getInstance("SHA256withRSA");
			verifier.initVerify(groupServer_publicKey);
			verifier.update(this.extractTokenInfo());
			return verifier.verify(sig1);
		}
		catch(Exception exception) 
		{
			System.out.println("Error: " + exception.getMessage());
			exception.printStackTrace();
		}
		return false;
	}

	public void setSIG2(PublicKey fileServer_publicKey, PrivateKey groupServer_privateKey)
	{
		try
		{
			Signature signer = Signature.getInstance("SHA256withRSA");
			signer.initSign(groupServer_privateKey);
			signer.update(fileServer_publicKey.getEncoded());
			sig2 = signer.sign();
		}
		catch(Exception exception) 
		{
			System.out.println("Error: " + exception.getMessage());
			exception.printStackTrace();
		}
	}
	
	public boolean auth_SIG2(PublicKey fileServer_publicKey,PublicKey groupServer_publicKey)
	{
		try
		{
			Signature verifier = Signature.getInstance("SHA256withRSA");
			verifier.initVerify(groupServer_publicKey);
			verifier.update(fileServer_publicKey.getEncoded());
			return verifier.verify(sig2);
		}
		catch(Exception exception) 
		{
			System.out.println("Error: " + exception.getMessage());
			exception.printStackTrace();
		}		
		return false;
	}	
}
