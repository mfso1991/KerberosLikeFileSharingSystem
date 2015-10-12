
/*
 *	Arbitrator class, as its name implies, is an union of kernel mechanisms authenticating, managing and revoking for the group/file servers. 
 *	The names of methods and parameters are deliberately chosen so that they are self-explanatory.
 */
 
import java.io.*;
import java.util.*;
import java.math.*;
import javax.crypto.*;
import java.security.*;
import javax.crypto.spec.*;

public class Arbitrator implements java.io.Serializable
{
	private SecureRandom random = new SecureRandom();
	private static final long serialVersionUID = 7600343803563417992L;
	private Hashtable<String, byte[]> passwordField = new Hashtable<String, byte[]>(); //It is unsurprising that passwords are not stored in plain text but in hashed byte[]. 
	private Hashtable<String, UserToken> userField = new Hashtable<String, UserToken>(); //Each user token is binding with user ID. 
	private Hashtable<String, ArrayList<String>> groupField = new Hashtable<String, ArrayList<String>>(); //The list contains names of group members.
	
	//The inner hash table are bindings between file shared in the group and the necessary crypto info for en/de-cryption. 
	private Hashtable<String, Hashtable<String, Envelope>> fileField = new Hashtable<String, Hashtable<String, Envelope>>(); 
	
	public synchronized void createUser(String username, byte[] digest) //Initially, the digest is the SHA256 value of the user name
	{	
		UserToken newUserToken = new UserToken(username);
		userField.put(username, newUserToken);
		passwordField.put(username, digest);
	}

	public synchronized void deleteUser(String username) throws Exception
	{
		ArrayList<String> ownedGroups = new ArrayList<String>(userField.get(username).getGroupsOwnedByUser());
		for(String og : ownedGroups)
			deleteGroup(og);
		//Groups that are accessible to user contains groups that user is in and ones user owns.
		ArrayList<String> groupsStillAccessible = new ArrayList<String>(userField.get(username).getUserAccessibleGroups()); 
		for(String gsa : groupsStillAccessible)
			groupField.get(gsa).remove(username);
		userField.remove(username);
		passwordField.remove(username);
	}
	
	public synchronized void changePassword(String username, byte[] digest)
	{
		passwordField.put(username, digest);
	}
	
	public synchronized boolean authenticateUser(String username, byte[] digest)
	{
		if(this.isUserExisting(username) && passwordField.containsKey(username))
			return Arrays.equals(digest, passwordField.get(username));
		return false;
	}

	public synchronized boolean isUserExisting(String username)
	{
		return userField.containsKey(username);
	}
	
	public synchronized void setUserToken(String username, UserToken token)
	{
		userField.put(username, token);
	}
	
	public synchronized UserToken getUserToken(String username)
	{
		return new UserToken(userField.get(username));
	}
		
	public synchronized void createGroup(String requester, String groupname) throws Exception
	{
		userField.get(requester).addOwnership(groupname);
		ArrayList<String> memberList = new ArrayList<String>();
		groupField.put(groupname, memberList);
		addUserToGroup(requester, groupname);
		fileField.put(groupname, new Hashtable<String, Envelope>());
	}

	public synchronized void addUserToGroup(String username, String groupname)
	{
		userField.get(username).addMembership(groupname);
		groupField.get(groupname).add(username);
	}
	
	public synchronized void deleteGroup(String groupname) throws Exception
	{
		ArrayList<String> members = new ArrayList<String>(groupField.get(groupname));
		for(String m : members)
			deleteUserFromGroup(m, groupname);
		groupField.remove(groupname);
		fileField.remove(groupname);
	}

	public synchronized void deleteUserFromGroup(String username, String groupname) throws Exception
	{
		userField.get(username).deAccess(groupname);
		groupField.get(groupname).remove(username);		
	}
	
	public synchronized boolean isGroupExisting(String groupname)
	{
		return groupField.containsKey(groupname);
	}
	
	public synchronized ArrayList<String> getGroupMembers(String groupname)
	{
		return new ArrayList<String>(groupField.get(groupname));
	}
	
	public synchronized Envelope generateNewFileCryptoInfo() throws Exception
	{
		/*
		 *	Using AES128 to en/de-crypt a file needs a key and a IV.
		 *	Packing key and IV in an Envelope object is more efficient than separately returning them.
		 */
			KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
			keyGenerator.init(128);
			Envelope env = new Envelope("FILECRYPTOINFO");
			env.addObject(keyGenerator.generateKey());
			byte[] IV = new byte[16];
			random.nextBytes(IV);
			env.addObject(IV);
			return env;
	}
	
	public synchronized void setFileCryptoInfo(String groupname, String filename) throws Exception
	{
		fileField.get(groupname).put(filename, this.generateNewFileCryptoInfo());	
	}
	
	public synchronized Envelope getFileCryptoInfo(String groupname, String filename)
	{
		return fileField.get(groupname).get(filename);
	}
}