

/*
 *	GroupThread acts on behalf of the GroupServer.
 *	It receives requests from GroupClient, authenticates the identity of the requester, and invokes the corresponding method. 
 */

import java.io.*;
import java.util.*;
import java.math.*;
import javax.crypto.*;
import java.security.*;
import java.net.Socket;
import java.lang.Thread;
import javax.crypto.spec.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class GroupThread extends Thread 
{
	private SecureRandom random = new SecureRandom();
	private final Socket socket;
	private GroupServer my_gs = null;
	private PublicKey publicKey = null;
	private PrivateKey privateKey = null;
	private long curtime = (new Date()).getTime()/1000;
	private int countForForcedSleeps = 0;
	private int countForOperations = 0;
	private Envelope rec = null;
	private Envelope req = null;
	private Envelope rep = null;
	private SecretKeySpec K_gi = null;
	private Cipher AES_Cipher = null;
	private byte[] IV = new byte[16];
	private UserToken token = null;
	private Key  K_cg = null; 
	private Mac Hmac = null;
	private long R_cg = 0; 
	
	public GroupThread(Socket _socket, GroupServer _gs, PrivateKey _prik, PublicKey _pubk)
	{
		socket = _socket;
		my_gs = _gs;
		privateKey = _prik;
		publicKey = _pubk;
	}

	public void run()
	{
		boolean proceed = true;
		Security.addProvider(new BouncyCastleProvider()); 
		R_cg = random.nextLong();
		
		try
		{
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
			
			do
			{
				rec = (Envelope)input.readObject(); //What GroupThread actually received. It is either in plain texts or in cipher texts. 
				System.out.println("Request received: " + rec.getMessage()); //Requests other than ones for fetching public key and hand-shaking are wrapped up in one name -- "REQ".
				
				if(rec.getMessage().equals("GPUB")) //Fetching public key of the group server. It is meant to be public, so no need for disguise. 
				{
					rep = new Envelope("OK");
					rep.addObject(publicKey);
					output.writeObject(rep);
				}
				else if(rec.getMessage().equals("DISCONNECT") || countForForcedSleeps >= 10) //Client wants to disconnect, or possible DoS attack occurred. 
				{																			 //The strictness can be tuned by changing 10 to other integers. 
					socket.close(); 
					proceed = false; 
				}	
				else if(rec.getMessage().equals("HANDSHAKING"))
				{
					Cipher RSA_Cipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA256AndMGF1Padding", "BC");
					RSA_Cipher.init(Cipher.DECRYPT_MODE, privateKey);
					K_gi = new SecretKeySpec(RSA_Cipher.doFinal((byte[])rec.getObjContents().get(0)), "HmacSHA1"); //Used for integrity check.
					K_cg = new SecretKeySpec(RSA_Cipher.doFinal((byte[])rec.getObjContents().get(1)), "AES"); //Session key will be used from now on by both GroupThread and GroupClient. 
					SealedObject sealedAuthInfoEnv = (SealedObject)rec.getObjContents().get(2); //It contains user name and SHA256 value of the password. 
					AES_Cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
					AES_Cipher.init(Cipher.DECRYPT_MODE, K_cg, new IvParameterSpec((byte[])rec.getObjContents().get(4)));
					Envelope authInfoEnvelope = (Envelope)sealedAuthInfoEnv.getObject(AES_Cipher);
					String username = (String)authInfoEnvelope.getObjContents().get(0);
					byte[] pwd = (byte[])authInfoEnvelope.getObjContents().get(1);
					
					//Start checking message integrity. 
					Hmac = Mac.getInstance("HmacSHA1");
					Hmac.init(K_gi);
					byte[] round_1 = Hmac.doFinal(K_gi.getEncoded());
					byte[] round_2 = Hmac.doFinal(K_cg.getEncoded());
					byte[] round_3 = Hmac.doFinal(((PublicKey)rec.getObjContents().get(5)).getEncoded());
					byte[] round_4 = Hmac.doFinal(username.getBytes("UTF-8"));
					byte[] round_5 = Hmac.doFinal(pwd);	
					if(!((new String(round_1) + new String(round_2) + new String(round_3) + new String(round_4) + new String(round_5))).equals((String)rec.getObjContents().get(3)))
					{
						rep = new Envelope("FAIL");
						rep.addObject("\n###### GroupServer HandShaking : Message has been garbled ######!\n");
						output.writeObject(rep);
					}				
					else
					{
						if(!my_gs.arbitrator.authenticateUser(username, pwd))
						{
							rep = new Envelope("FAIL");
							rep.addObject("\n######! GroupServer HandShaking : Invalid ID/Password combination ######!\n");
							output.writeObject(rep);
						}
						else
						{
							UserToken userToken = my_gs.arbitrator.getUserToken(username);
							userToken.setSIG1(privateKey); //sig1 will be generated each time requesting the fresh UserToken. 
							userToken.setSIG2((PublicKey)rec.getObjContents().get(5), privateKey); //sig2 will only be generated once to bind the user and the intended FileServer.
							my_gs.arbitrator.setUserToken(username, new UserToken(userToken));	
							rep = new Envelope("OK");
							rep.addObject(R_cg);
							SecuredSending(output);
						}
					}
				}
				else if(rec.getMessage().equals("REQ"))
				{
					SecuredReceiving(input); //Requests other than "GPUP" and "HANDSHAKING" are decrypted out.
											 //Checks UserToken integrity, message integrity, and possible replay or reorder attacks. 
					
					//Assumed to be a failure at the beginning. 
					rep = new Envelope("FAIL");
					
					if(req != null) //Would be null if and only if the either one of the three integrity checks has failed. 
					{
						if(req.getMessage().equals("GET")) //An existing user requests for his/her fresh UserToken.
						{								   //All other requests rely on fresh UserToken for synchronization. 
							String username = (String)req.getObjContents().get(0); 
							byte[] pwd = (byte[])req.getObjContents().get(1); 
							if(my_gs.arbitrator.authenticateUser(username, pwd)) //authenticateUser method checks the existence of the user name and ID/Password combination.
							{													 //Since all operations in GroupThread needs to invoke "GET" in advance, upon receiving, 
																				 //GroupThread needs not to check again. 
								UserToken userToken = my_gs.arbitrator.getUserToken(username);
								userToken.setSIG1(privateKey);
								my_gs.arbitrator.getUserToken(username);
								rep = new Envelope("OK");
								rep.addObject(new UserToken(userToken));
								my_gs.arbitrator.setUserToken(username, new UserToken(userToken));								
							}	
							else rep.addObject("\n###### Invalid ID/Password combination ######\n");
						}
						else if(req.getMessage().equals("CPWD")) //An existing user wants to change his/her password.
						{
							String username = (String)req.getObjContents().get(1);
							byte[] newPwd = (byte[])req.getObjContents().get(2);
							my_gs.arbitrator.changePassword(username, newPwd);
							rep = new Envelope("OK");
						}
						else if(req.getMessage().equals("CUSER")) //The Administrator wants to create a new user with an user name that has not been used yet. 
						{
							String username = (String)req.getObjContents().get(1);
							byte[] pwd = (byte[])req.getObjContents().get(2);
							if(!my_gs.arbitrator.isUserExisting(username)) 
							{
								/*
								 *	To authenticate the ADMIN, we check if the requester has created a group that names 
								 *	{"ADMIN"}_groupserver-preivateKey. The group is initially created by GroupServer for ADMIN. 
								 */
									Signature signer = Signature.getInstance("SHA256withRSA");
									signer.initSign(privateKey);
									signer.update("ADMIN".getBytes("UTF-8"));
									if(token.checkMembership(new String(signer.sign(), "UTF-8")))
									{
										my_gs.arbitrator.createUser(username, pwd);
										rep = new Envelope("OK"); 
									}
									else rep.addObject("\n###### You are not ADMIN. ######\n");
							}
							else rep.addObject("\n###### Please choose another user name. ######\n");
						}
						else if(req.getMessage().equals("DUSER")) //The Administrator wants to delete an existing user.
						{
							String username = (String)req.getObjContents().get(1);
							if(!my_gs.arbitrator.isUserExisting(username)) 
							{	
								Signature signer = Signature.getInstance("SHA256withRSA");
								signer.initSign(privateKey);
								signer.update("ADMIN".getBytes("UTF-8"));
								if(token.checkMembership(new String(signer.sign(), "UTF-8")))
								{
									my_gs.arbitrator.deleteUser(username);
									rep = new Envelope("OK"); 
								}
								else rep.addObject("\n###### You are not ADMIN. ######\n");
							}
							else rep.addObject("\n###### User to be deleted does not exist. ######\n");
						}
						else if(req.getMessage().equals("CGROUP")) //An existing user wants to create a group that does not exist. 
						{
							String groupname = (String)req.getObjContents().get(1);
							if(!my_gs.arbitrator.isGroupExisting(groupname))
							{
								my_gs.arbitrator.createGroup(token.getUserID(), groupname);
								rep = new Envelope("OK");
							}
							else rep.addObject("\n###### Please choose another group name. ######\n");
						}
						else if(req.getMessage().equals("DGROUP")) //The owner of an existing group wants to delete the group.
						{
							String groupname = (String)req.getObjContents().get(1);
							if(my_gs.arbitrator.isGroupExisting(groupname))
							{
								if(token.checkOwnership(groupname))
								{
									my_gs.arbitrator.deleteGroup(groupname);
									rep = new Envelope("OK");
								}
								else rep.addObject("\n###### You don't have right to do so. ######\n");
							}			
							else rep.addObject("\n###### Group does not exist. ######\n");
						}
						else if(req.getMessage().equals("LMEMBERS")) //A member of an existing group wants the list of all group members.
						{
							ArrayList<String> toBeSent = null;
							String groupname = (String)req.getObjContents().get(1);
							String username = token.getUserID();
							if(my_gs.arbitrator.isGroupExisting(groupname))
							{
								if(token.checkMembership(groupname))
								{
									toBeSent = new ArrayList<String>(my_gs.arbitrator.getGroupMembers(groupname));
									rep = new Envelope("OK");	
									rep.addObject(toBeSent);
								}
								else rep.addObject("\n###### You are not a member of this group. ######\n");
							}
							else rep.addObject("\n###### Group does not exist. ######\n");
						}
						else if(req.getMessage().equals("AUSERTOGROUP")) //The owner of an existing group wants to add an existing user in the system into the group.
						{
							String toBeAdded = (String)req.getObjContents().get(1);
							String groupname = (String)req.getObjContents().get(2);
							if(my_gs.arbitrator.isGroupExisting(groupname))
							{
								if(token.checkOwnership(groupname))
								{
									if(my_gs.arbitrator.isUserExisting(toBeAdded))
									{
										if(!my_gs.arbitrator.getGroupMembers(groupname).contains(toBeAdded))
										{
											my_gs.arbitrator.addUserToGroup(toBeAdded, groupname);
											rep = new Envelope("OK");	
										}
										else rep.addObject("\n###### He/She was already a member. ######\n");
									}
									else rep.addObject("\n###### He/She is not a registered user. ######\n");
								}
								else rep.addObject("\n###### You don't have right to do so. ######\n");
							}
							else rep.addObject("\n###### Group does not exist. ######\n");
						}
						else if(req.getMessage().equals("RUSERFROMGROUP")) //The owner of an existing group wants to revoke an existing member of the group.
						{
							String toBeDeleted = (String)req.getObjContents().get(1);
							String groupname = (String)req.getObjContents().get(2);
							if(my_gs.arbitrator.isGroupExisting(groupname))
							{
								if(token.checkOwnership(groupname))
								{
									if(my_gs.arbitrator.isUserExisting(toBeDeleted))
									{
										if(my_gs.arbitrator.getGroupMembers(groupname).contains(toBeDeleted))
										{
											if(!my_gs.arbitrator.getUserToken(toBeDeleted).checkOwnership(groupname))
											{
												my_gs.arbitrator.deleteUserFromGroup(toBeDeleted, groupname);
												rep = new Envelope("OK");
											}
											else rep.addObject("\n###### He/She is also an owner. ######\n");
										}
										else rep.addObject("\n###### He/She is not a member. ######\n");
									}
									else rep.addObject("\n###### He/She is not a registered user. ######\n");
								}
								else rep.addObject("\n###### You don't have right to do so. ######\n");
							}
							else rep.addObject("\n###### Group does not exist. ######\n");
						}
						else if(req.getMessage().equals("FCRYPINFO")) //To en/de-crypt a file, the associated crypto-info is needed.
						{
							String groupname = (String)req.getObjContents().get(1);
							String username = token.getUserID();
							if(my_gs.arbitrator.isGroupExisting(groupname))
							{
								if(token.checkMembership(groupname))
								{
									String filename = (String)req.getObjContents().get(2);
									rep = new Envelope("OK");
									if((boolean)req.getObjContents().get(3))
										my_gs.arbitrator.setFileCryptoInfo(groupname, filename);
									rep.addObject(my_gs.arbitrator.getFileCryptoInfo(groupname, filename));
								}
								else rep.addObject("\n###### You are not a member. ######\n");
							}
							else rep.addObject("\n###### Group does not exist. ######\n");
						}						
					}
					SecuredSending(output);
				}
			}
			while(proceed);	
		}
		catch(Exception exception)
		{
			System.err.println("ERROR : " + exception.getMessage());
			exception.printStackTrace(System.err);
		}
	}
		private byte[] serialize(Object object) throws Exception
		{
			ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
			ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
			objectOutputStream.writeObject(object);
			return byteArrayOutputStream.toByteArray();
		}
		
		private void SecuredSending(ObjectOutputStream output)
		{
			try 
			{
				rep.addObject(R_cg++);
				byte[] IV = new byte[16];
				random.nextBytes(IV);
				Cipher AES_Cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
				AES_Cipher.init(Cipher.ENCRYPT_MODE, K_cg, new IvParameterSpec(IV));
				SealedObject sealedObject = new SealedObject(rep, AES_Cipher);
				Envelope groupServerReply = new Envelope("REP");
				groupServerReply.addObject(sealedObject);
				groupServerReply.addObject(new String(Hmac.doFinal(serialize(sealedObject))));
				groupServerReply.addObject(IV);
				output.writeObject(groupServerReply);
			}
			catch(Exception exception) 
			{
				System.out.println("ERROR : " + exception.getMessage());
				exception.printStackTrace();
			}
		}
		
		private void SecuredReceiving(ObjectInputStream input)
		{
			countForOperations++;
			if((new Date()).getTime()/1000 - curtime > 10 && countForOperations > 100)
			{
				try
				{
					System.out.println("### Sleep ###");
					Thread.sleep(10 * 1000);
					countForOperations = 0;
					curtime = (new Date()).getTime()/1000;
					countForForcedSleeps++;
				}
				catch(Exception exception) 
				{
					System.out.println("Error: " + exception.getMessage());
					exception.printStackTrace();
				}	
			}
			try
			{
				SealedObject sealedObject = (SealedObject)rec.getObjContents().get(0);
				if(!new String(Hmac.doFinal(serialize(sealedObject))).equals((String)rec.getObjContents().get(1)))
				{
					req = new Envelope("FAIL");
					req.addObject("###### GROUPSERVER ERROR : GARBLED_MESSAGE ######");
				}
				else
				{
					byte[] IV = (byte[])rec.getObjContents().get(2);
					Cipher AES_Cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
					AES_Cipher.init(Cipher.DECRYPT_MODE, K_cg, new IvParameterSpec(IV));
					req = (Envelope)sealedObject.getObject(AES_Cipher);
					if(R_cg++ != (long)req.getObjContents().get(req.getObjContents().size() - 1))
					{
						req = new Envelope("FAIL");
						req.addObject("###### GROUPSERVER ERROR : REPLAY/REORDER_ATTACK ######");
					}
					if(!req.getMessage().equals("GET"))
					{
						token = (UserToken)req.getObjContents().get(0);
						if(!token.auth_SIG1(publicKey))
						{
							req = new Envelope("FAIL");
							req.addObject("###### GROUPSERVER ERROR : BAD_TOKEN ######");
						}
					}
				}
			}
			catch(Exception exception) 
			{
				System.out.println("ERROR : " + exception.getMessage());
				exception.printStackTrace();
			}
		}
}
