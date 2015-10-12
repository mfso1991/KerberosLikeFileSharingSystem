
/******************************************************************************************************************************************************/
/************************************************************* Art_OF_You Zhou ************************************************************************/
/******************************************************************************************************************************************************/

import java.io.*;
import java.math.*;
import java.util.*;
import javax.crypto.*;
import java.security.*;
import java.net.Socket;
import java.lang.Thread;
import javax.crypto.spec.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class FileThread extends Thread
{
	private long curtime = (new Date()).getTime()/1000;
	private SecureRandom random = new SecureRandom();
	private PublicKey groupServer_publicKey = null;
	private int countForForcedSleeps = 0;
	private PrivateKey privateKey = null;
	private int countForOperations = 0;	
	private PublicKey publicKey = null;
	private SecretKeySpec K_fi = null;
	private UserToken token = null;
	private byte[] IV_file = null;
	private Envelope rec = null;
	private Envelope req = null;
	private Envelope rep = null;
	private final Socket socket;
	private Key  K_file = null;
	private Key  K_cf = null;
	private Mac Hmac = null;
	private long R_cf; 
	
	public FileThread(Socket _socket, PrivateKey _prik, PublicKey _pubk)
	{
		socket = _socket;
		privateKey = _prik;
		publicKey = _pubk;
	}

	public void run()
	{
		boolean proceed = true;
		try
		{
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());

			do
			{
				rec = (Envelope)input.readObject();
				System.out.println("***** FILESERVER RECEIVED REQUEST : " + rec.getMessage() + " *****");
		
				if(rec.getMessage().equals("GETFPUB"))
				{
					rep = new Envelope("OK");
					rep.addObject(publicKey);
					output.writeObject(rep);
				}
				else if(rec.getMessage().equals("DISCONNECT") || countForForcedSleeps >= 10)
				{
					socket.close();
					proceed = false;
					//System.exit(0);
				}
				else if(rec.getMessage().equals("HANDSHAKING"))
				{
					/*
					 *	DECRYPTING {K_fi}K_f || {K_cf}K_f
					 */
						Cipher RSA_Cipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA256AndMGF1Padding", "BC");
						RSA_Cipher.init(Cipher.DECRYPT_MODE, privateKey);
						K_fi = new SecretKeySpec(RSA_Cipher.doFinal((byte[])rec.getObjContents().get(0)), "HmacSHA1");
						K_cf = new SecretKeySpec(RSA_Cipher.doFinal((byte[])rec.getObjContents().get(1)), "AES");
					/*	
					 *	DECRYPTING {R_cf || UserToken}K_cf
					 */
						SealedObject sealedAuthInfoEnv = (SealedObject)rec.getObjContents().get(2);
						Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
						cipher.init(Cipher.DECRYPT_MODE, K_cf, new IvParameterSpec((byte[])rec.getObjContents().get(4)));
						Envelope authInfoEnvelope = (Envelope)sealedAuthInfoEnv.getObject(cipher);
						R_cf = (long)authInfoEnvelope.getObjContents().get(0);
						token = (UserToken)authInfoEnvelope.getObjContents().get(1);
					/*
					 *	GroupServer's PublicKey
					 */
						groupServer_publicKey = (PublicKey)rec.getObjContents().get(5);				
							/*
							 *	Integrity Check
							 */
								Hmac = Mac.getInstance("HmacSHA1");
								Hmac.init(K_fi);
								byte[] hmac_1 = Hmac.doFinal(K_fi.getEncoded());
								byte[] hmac_2 = Hmac.doFinal(K_cf.getEncoded());
								byte[] hmac_3 = Hmac.doFinal(Long.toString(R_cf).getBytes("UTF-8"));
								if(!(new String(hmac_1) + new String(hmac_2) + new String(hmac_3)).equals((String)rec.getObjContents().get(3)))
								{
									rep = new Envelope("FAIL");
									rep.addObject("###### ERROR : GARBLED_MESSAGE ######");
								}					
								else
								{
									if(!token.auth_SIG1(groupServer_publicKey) || !token.auth_SIG2(publicKey, groupServer_publicKey))
									{
										rep = new Envelope("FAIL");
										rep.addObject("###### FILESERVER ERROR : BAD_TOKEN ######");
									}
									else
									{
										rep = new Envelope("OK");
										rep.addObject(R_cf++);
									}
								}
								
					output.writeObject(rep);
				}
				else if(rec.getMessage().equals("REQ"))
				{
					SecuredReceiving(input);
					rep = new Envelope("FAIL");
					if(!req.getMessage().equals("FAIL"))
					{
						if(req.getMessage().equals("LISTFILES"))
						{
							rep = new Envelope("OK");
							ArrayList<String> returnObject = new ArrayList<String>();
							ArrayList<String> accessibleGroups = new ArrayList<String>(token.getUserAccessibleGroups());
							Iterator<SharedFile> iter = FileServer.filePriorityQueue.getFiles();
							SharedFile sf = null;
							while(iter.hasNext())
								if(accessibleGroups.contains((sf = iter.next()).getGroup()))
									returnObject.add("Group: " + sf.getGroup() + " | Owner: " + sf.getOwner() + " | File Path: " + sf.getPath());
							rep.addObject(new ArrayList<String>(returnObject)); 
						}
						else if (req.getMessage().equals("DELETEFILE")) 
						{
							String remotePath = (String)req.getObjContents().get(1);
							SharedFile sf = FileServer.filePriorityQueue.getFile(new SharedFile("/"+remotePath));
							if (sf == null) 
								rep.addObject("###### ERROR : FILE_DOES_NOT_EXIST_ON_FILESERVER ######");
							else
							{
								File file = new File("shared_files/"+remotePath);
								if (!file.exists()) 
									rep.addObject("###### DELETEFILE ERROR : FILE_DOES_NOT_EXIST_ON_DISK ######");
								else
								{
									if (file.delete()) 
									{
										if(FileServer.filePriorityQueue.removeFile(sf))
											rep = new Envelope("OK");
										else
											rep.addObject("###### ERROR : CAN_NOT_DELETE_FILE_FROM_FILE_PRIORITY_QUEUE ######");
									}
									else 
										rep.addObject("###### ERROR : CAN_NOT_DELETE_FILE_FROM_DISK ######");
								}
							}
						}
						else if(req.getMessage().equals("DELETEASSOCIATEDFILES"))
						{
							String groupname = (String)req.getObjContents().get(1);
							Iterator<SharedFile> iter = FileServer.filePriorityQueue.getFiles();
							SharedFile sf = null;
							while(iter.hasNext())
								if((sf = iter.next()).getGroup().equals(groupname))
								{
									if(FileServer.filePriorityQueue.removeFile(sf))
										System.out.println("***" + sf.getPath() + " is deleted successfully from the file list. ***\n");
									else 
										System.out.println("\n###### Failed to delete " + sf.getPath() + " from the file list. ######\n");
									
									File f = new File("shared_files/"+sf.getPath());
									if (f.exists())
									{
										if(f.delete())
										{
											System.out.println("\n*** " + sf.getPath() + " is deleted successfully from the disk. ***\n");
										}
										else
											System.out.println("\n###### Failed to delete " + sf.getPath() + " from the disk. ######\n");
									}
									else
										System.out.println("\n###### " + sf.getPath() + " was not found######\n");
								}							
							rep = new Envelope("OK");
						}
						else if(req.getMessage().equals("GETENDF"))
						{
							if(FileServer.filePriorityQueue.isEmpty())
								rep.addObject("###### ERROR : EMPTY_FILE_PRIORITY_QUEUE ######");
							else
							{
								rep = new Envelope("OK");
								rep.addObject(FileServer.filePriorityQueue.peek().getPath());
							}
						}
						else if(req.getMessage().equals("UPLOADFILE"))
						{
							String remotePath = (String)req.getObjContents().get(1);
							if (FileServer.filePriorityQueue.checkFile(new SharedFile(remotePath))) 
								rep.addObject("###### ERROR : FILE_ALREADY_EXISTED_ON_FILESERVER ######");
							else
							{
								String groupname = (String)req.getObjContents().get(2);
								Envelope env = (Envelope)req.getObjContents().get(3);						
								Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
								cipher.init(Cipher.ENCRYPT_MODE, (Key)env.getObjContents().get(0), new IvParameterSpec((byte[])env.getObjContents().get(1)));
								File file = new File("shared_files/"+remotePath);
								file.createNewFile();
								FileOutputStream fos = new FileOutputStream(file);
								System.out.printf("Successfully created file %s\n", remotePath);

								rep = new Envelope("READY"); 
								SecuredSending(output);
								
								rec = (Envelope)input.readObject();
								SecuredReceiving(input);
								while(req.getMessage().equals("FEEDINGBYTES")) 
								{
									fos.write(cipher.doFinal((byte[])req.getObjContents().get(1)), 0, (Integer)req.getObjContents().get(2));
									rep = new Envelope("CONTINUE"); //Success
									SecuredSending(output);
									rec = (Envelope)input.readObject();
									SecuredReceiving(input);
								}
								fos.close();
								
								FileServer.filePriorityQueue.addFile(token.getUserID(), groupname, remotePath, (new Date()).getTime()/1000);
								rep = new Envelope("OK");
							}
						}
						else if (req.getMessage().equals("DOWNLOADFILE")) 
						{
							String remotePath = (String)req.getObjContents().get(1);
							SharedFile sf = FileServer.filePriorityQueue.getFile(new SharedFile("/"+remotePath));
							if (sf == null) 
								rep.addObject("###### ERROR : FILE_DOES_NOT_EXIST_ON_FILESERVER ######");
							else
							{
								sf.addCount();
								Envelope env = (Envelope)req.getObjContents().get(2);
								Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
								cipher.init(Cipher.DECRYPT_MODE, (Key)env.getObjContents().get(0), new IvParameterSpec((byte[])env.getObjContents().get(1)));
								
								File file = new File("shared_files/"+remotePath);
								if (!file.exists()) 
									rep.addObject("###### DOWNLOADFILE ERROR : FILE_DOES_NOT_EXIST_ON_DISK ######");
								else
								{
									FileInputStream fis = new FileInputStream(file);
									do 
									{
										byte[] buf = new byte[4096];
										int n = fis.read(buf);
										if (n < 0) 
										{
											rep.addObject("###### Error Reading File ######");
											SecuredSending(output);
										}
										else if (n > 0)
										{
											rep = new Envelope("WRITINGBYTES");
											rep.addObject(cipher.doFinal(buf));
											rep.addObject(new Integer(n));

											SecuredSending(output);
											
											rec = (Envelope)input.readObject();
											SecuredReceiving(input);

										}
									}
									while (fis.available() > 0);		 
												 
									rep = new Envelope("END_OF_FILE");
								}
							}	
						}		
						else if (req.getMessage().equals("GETFILEGROUP"))
						{
							String remotePath = (String)req.getObjContents().get(1);
							SharedFile sf = FileServer.filePriorityQueue.getFile(new SharedFile("/"+remotePath));
							if (sf == null) 
								rep.addObject("\n###### File " + remotePath + " does not exist in FileServer ######\n");
							else
							{
								rep = new Envelope("OK");
								rep.addObject(sf.getGroup());
							}
						}
					}
					SecuredSending(output);
				}
			} while(proceed);
		}
		catch(Exception exception)
		{
			System.err.println("Error: " + exception.getMessage());
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
				rep.addObject(R_cf++);
				byte[] IV = new byte[16];
				random.nextBytes(IV);
				Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
				cipher.init(Cipher.ENCRYPT_MODE, K_cf, new IvParameterSpec(IV));
				SealedObject sealedObject = new SealedObject(rep, cipher);
				Envelope fileServerReply = new Envelope("REP");
				fileServerReply.addObject(sealedObject);
				fileServerReply.addObject(new String(Hmac.doFinal(serialize(sealedObject))));
				fileServerReply.addObject(IV);
				output.writeObject(fileServerReply);
			}
			catch(Exception exception) 
			{
				System.out.println("Error: " + exception.getMessage());
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
					req.addObject("###### ERROR : GARBLED_MESSAGE ######");
				}
				else
				{
					byte[] IV = (byte[])rec.getObjContents().get(2);
					Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
					cipher.init(Cipher.DECRYPT_MODE, K_cf, new IvParameterSpec(IV));
					req = (Envelope)sealedObject.getObject(cipher);
					if(R_cf++ != (long)req.getObjContents().get(req.getObjContents().size() - 1))
					{
						req = new Envelope("FAIL");
						req.addObject("###### ERROR : REPLAY/REORDER_ATTACK ######");
					}
					token = (UserToken)req.getObjContents().get(0);
					if(!token.auth_SIG1(groupServer_publicKey) || !token.auth_SIG2(publicKey, groupServer_publicKey))
					{
						req = new Envelope("FAIL");
						req.addObject("###### ERROR : BAD_TOKEN ######");
					}
				}
			}
			catch(Exception exception) 
			{
				System.out.println("Error: " + exception.getMessage());
				exception.printStackTrace();
			}
		}
}
