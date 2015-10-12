

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.util.*;
import java.io.*;
import java.security.*;
import java.math.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class GroupClient extends Client
{
	private SecureRandom random = new SecureRandom();
	private SecretKeySpec K_gi = null;
	private long R_cg; 
	private Key  K_cg = null; 
	private Envelope rep = null;
	private Envelope req = null;
	private Mac Hmac = null;
	private Cipher AES_Cipher = null;
	private byte[] IV = new byte[16];
	private UserToken token = null;
	
	public boolean handShaking(byte[] keyForHMAC, Key AES128, PublicKey fileServer_publicKey, String username, byte[] pwd)
	{
		Security.addProvider(new BouncyCastleProvider());
		try
		{
			K_gi = new SecretKeySpec(keyForHMAC, "HmacSHA1");
			K_cg = AES128;
		
			Envelope req = new Envelope("HANDSHAKING");
			
			Cipher RSA_Cipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA256AndMGF1Padding", "BC");
			RSA_Cipher.init(Cipher.ENCRYPT_MODE, fetchPublicKey());
			req.addObject(RSA_Cipher.doFinal(keyForHMAC));
			req.addObject(RSA_Cipher.doFinal(AES128.getEncoded()));
			System.out.println("***** Keys to be sent have been packed cryptographically *****");
			
			Envelope authInfoEnv = new Envelope("AUTHINFO");
			authInfoEnv.addObject(username);
			authInfoEnv.addObject(pwd);
			random.nextBytes(IV);
			AES_Cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
			AES_Cipher.init(Cipher.ENCRYPT_MODE, K_cg, new IvParameterSpec(IV));
			SealedObject sealedAuthInfoEnv = new SealedObject(authInfoEnv, AES_Cipher);
			req.addObject(sealedAuthInfoEnv);
			System.out.println("***** Info for user authentication has been packed cryptographically *****");
		
			Hmac = Mac.getInstance("HmacSHA1");
			Hmac.init(K_gi);
			byte[] round_1 = Hmac.doFinal(K_gi.getEncoded());
			byte[] round_2 = Hmac.doFinal(K_cg.getEncoded());
			byte[] round_3 = Hmac.doFinal(fileServer_publicKey.getEncoded());
			byte[] round_4 = Hmac.doFinal(username.getBytes("UTF-8"));
			byte[] round_5 = Hmac.doFinal(pwd);
			req.addObject(new String(round_1) + new String(round_2) + new String(round_3) + new String(round_4) + new String(round_5));
			System.out.println("***** HMACSHA1 VALUE GENERATED *****");
			
			req.addObject(IV);
			System.out.println("***** AES IV INSERTED *****");
			
			req.addObject(fileServer_publicKey);
			System.out.println("***** FileServer Public Key INSERTED *****");
			
			output.writeObject(req);		
		
				Envelope groupServerReply = (Envelope)input.readObject();
				if(groupServerReply.getMessage().equals("FAIL"))
					return false;
				SealedObject sealedObject = (SealedObject)groupServerReply.getObjContents().get(0);
				if(!new String(Hmac.doFinal(serialize(sealedObject))).equals((String)groupServerReply.getObjContents().get(1)))
				{
					rep = new Envelope("FAIL");
					rep.addObject(rep.getObjContents().get(0));
				}
				else
				{
					byte[] IV = (byte[])groupServerReply.getObjContents().get(2);
					Cipher AES_Cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
					AES_Cipher.init(Cipher.DECRYPT_MODE, K_cg, new IvParameterSpec(IV));
					rep = (Envelope)sealedObject.getObject(AES_Cipher);
					R_cg = (long)rep.getObjContents().get(0);
					R_cg++;
					return true;
				}
		}
		catch(Exception exception)
		{
			System.err.println(exception.getMessage());
			exception.printStackTrace(System.err);
		}
		return false;
	}
	
	public PublicKey fetchPublicKey() 
	{
		try 
		{
			Envelope req = new Envelope("GPUB");
			output.writeObject(req);
			Envelope rep = (Envelope)input.readObject();
			if(rep.getMessage().equals("OK"))
				return (PublicKey)rep.getObjContents().get(0);
			return null;
		}
		catch(Exception exception) 
		{
			System.err.println("Error: " + exception.getMessage());
			exception.printStackTrace(System.err);
			return null;
		}
	}

	public boolean changePwd(String username, byte[] newPwd, UserToken token)
	{
		try
		{
			req = new Envelope("CPWD");
			req.addObject(new UserToken(token));
			req.addObject(username);
			req.addObject(newPwd); 
			
			SecuredSending(output);
			SecuredReceiving(input);
			
			if(rep.getMessage().equals("FAIL"))
			{
				System.out.println((String)rep.getObjContents().get(0));
				return false;
			}
			return true;
		}
		catch(Exception exception)
		{
			System.err.println("Error: " + exception.getMessage());
			exception.printStackTrace(System.err);
			return false;
		}
	}
	 
	public UserToken getToken(String username, byte[] pwd)
	{
		try
		{
			req = new Envelope("GET");
			req.addObject(username);
			req.addObject(pwd);
				
			SecuredSending(output);
			SecuredReceiving(input);
			
			if(rep.getMessage().equals("FAIL"))
			{
				System.out.println((String)rep.getObjContents().get(0));
				return new UserToken("RETARDED");
			}
			return (UserToken)rep.getObjContents().get(0);
		}
		catch(Exception exception)
		{
			System.err.println("Error: " + exception.getMessage());
			exception.printStackTrace(System.err);
			return null;
		}
	}
	 
	public boolean createUser(String username, byte[] pwd, UserToken token)
	{
		try
		{
			req = new Envelope("CUSER");
			req.addObject(new UserToken(token));
			req.addObject(username);
			req.addObject(pwd); 

			SecuredSending(output);
			SecuredReceiving(input);

			if(rep.getMessage().equals("FAIL"))
			{
				System.out.println((String)rep.getObjContents().get(0));
				return false;
			}
			return true;			

		}
		catch(Exception exception)
		{
			System.err.println("Error: " + exception.getMessage());
			exception.printStackTrace(System.err);
			return false;
		}
	}
	 
	public boolean deleteUser(String username, UserToken token)
	{
		try
		{
			req = new Envelope("DUSER");
			req.addObject(new UserToken(token));
			req.addObject(username); 

			SecuredSending(output);
			SecuredReceiving(input);
				
			if(rep.getMessage().equals("FAIL"))
			{
				System.out.println((String)rep.getObjContents().get(0));
				return false;
			}
			return true;
		}
		catch(Exception exception)
		{
			System.err.println("Error: " + exception.getMessage());
			exception.printStackTrace(System.err);
			return false;
		}
	}
	 
	public boolean createGroup(String groupname, UserToken token)
	{
		try
		{
			req = new Envelope("CGROUP");
			req.addObject(new UserToken(token));
			req.addObject(groupname); 

			SecuredSending(output);
			SecuredReceiving(input);
				
			if(rep.getMessage().equals("FAIL"))
			{
				System.out.println((String)rep.getObjContents().get(0));
				return false;
			}
			return true;
		}
		catch(Exception exception)
		{
			System.err.println("Error: " + exception.getMessage());
			exception.printStackTrace(System.err);
			return false;
		}
	}
	 
	public boolean deleteGroup(String groupname, UserToken token)
	{
		try
		{
			req = new Envelope("DGROUP");
			req.addObject(new UserToken(token));
			req.addObject(groupname); 

			SecuredSending(output);
			SecuredReceiving(input);
				
			if(rep.getMessage().equals("FAIL"))
			{
				System.out.println((String)rep.getObjContents().get(0));
				return false;
			}
			return true;
		}
		catch(Exception exception)
		{
			System.err.println("Error: " + exception.getMessage());
			exception.printStackTrace(System.err);
			return false;
		}
	}
	 
	@SuppressWarnings("unchecked")
	public ArrayList<String> listMembers(String groupname, UserToken token)
	{
		try
		{
			req = new Envelope("LMEMBERS");
			req.addObject(new UserToken(token));
			req.addObject(groupname);
				
			SecuredSending(output);
			SecuredReceiving(input);
			
			if(rep.getMessage().equals("FAIL"))
			{
				System.out.println((String)rep.getObjContents().get(0));
				return new ArrayList<String>();
			}
			return (ArrayList<String>)rep.getObjContents().get(0);
		}
		catch(Exception exception)
		{
			System.err.println("Error: " + exception.getMessage());
			exception.printStackTrace(System.err);
			return null;
		}
	}
	 
	public boolean addUserToGroup(String username, String groupname, UserToken token)
	{
		try
		{
			req = new Envelope("AUSERTOGROUP");
			req.addObject(new UserToken(token));
			req.addObject(username);
			req.addObject(groupname); 

			SecuredSending(output);
			SecuredReceiving(input);
				
			if(rep.getMessage().equals("FAIL"))
			{
				System.out.println((String)rep.getObjContents().get(0));
				return false;
			}
			return true;
		}
		catch(Exception exception)
		{
			System.err.println("Error: " + exception.getMessage());
			exception.printStackTrace(System.err);
			return false;
		}
	}
	 
	public boolean deleteUserFromGroup(String username, String groupname, UserToken token)
	{
		try
		{
			req = new Envelope("RUSERFROMGROUP");
			req.addObject(new UserToken(token));
			req.addObject(username);
			req.addObject(groupname); 

			SecuredSending(output);
			SecuredReceiving(input);
				
			if(rep.getMessage().equals("FAIL"))
			{
				System.out.println((String)rep.getObjContents().get(0));
				return false;
			}
			return true;
		}
		catch(Exception exception)
		{
			System.err.println("Error: " + exception.getMessage());
			exception.printStackTrace(System.err);
			return false;
		}
	}
	 
	public Envelope getFileCryptoInfo(String groupname, UserToken token, String fileDes, boolean upload)
	{
			try
			{
				req = new Envelope("FCRYPINFO");
				req.addObject(new UserToken(token));
				req.addObject(groupname);
				req.addObject(fileDes);
				req.addObject(upload);
				
				SecuredSending(output);
				SecuredReceiving(input);
				
				if(rep.getMessage().equals("FAIL"))
				{
					System.out.println((String)rep.getObjContents().get(0));
					return null;
				}
				return (Envelope)rep.getObjContents().get(0);
			}
			catch(Exception exception)
			{
				System.err.println("Error: " + exception.getMessage());
				exception.printStackTrace(System.err);
			}	
			return null;
	}

		
		/************************************************************/
		/***************************	  KERNEL METHODS 	 *****************************/
		/************************************************************/
		
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
				req.addObject(R_cg++);
				Cipher AES_Cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
				byte[] IV = new byte[16];
				random.nextBytes(IV);
				AES_Cipher.init(Cipher.ENCRYPT_MODE, K_cg, new IvParameterSpec(IV));
				SealedObject sealedObject = new SealedObject(req, AES_Cipher);
				Envelope groupClientRequest = new Envelope("REQ");
				groupClientRequest.addObject(sealedObject);
				groupClientRequest.addObject(new String(Hmac.doFinal(serialize(sealedObject))));
				groupClientRequest.addObject(IV);
				output.writeObject(groupClientRequest);
			}
			catch(Exception exception) 
			{
				System.out.println("Error: " + exception.getMessage());
				exception.printStackTrace();
			}
		}
						
		private void SecuredReceiving(ObjectInputStream input)
		{
			try
			{
				Envelope groupServerReply = (Envelope)input.readObject();
				SealedObject sealedObject = (SealedObject)groupServerReply.getObjContents().get(0);
				if(!new String(Hmac.doFinal(serialize(sealedObject))).equals((String)groupServerReply.getObjContents().get(1)))
				{
					rep = new Envelope("FAIL");
					rep.addObject("###### GROUPCLIENT ERROR : GARBLED_MESSAGE ######");
				}
				else
				{
					byte[] IV = (byte[])groupServerReply.getObjContents().get(2);
					Cipher AES_Cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
					AES_Cipher.init(Cipher.DECRYPT_MODE, K_cg, new IvParameterSpec(IV));
					rep = (Envelope)sealedObject.getObject(AES_Cipher);
					if(R_cg++ != (long)rep.getObjContents().get(rep.getObjContents().size() - 1))
					{
						rep = new Envelope("FAIL");
						rep.addObject("###### GROUPCLIENT ERROR : REPLAY/REORDER_ATTACK ######");
					}
				}
			}
			catch(Exception exception) 
			{
				System.out.println("Error: " + exception.getMessage());
				exception.printStackTrace();
			}
		}
						
	public void CommuThruSecuredChannel(int expectedS, int expectedR, String operationName)
	{
		try
		{
			System.out.printf("\n*****\tExpected_#_(%d)\tActual_#_(%d)\t--->\t%s_PARAMETERS_EXCHANGE_STARTS\t--->\t*****\n", expectedS, req.getObjContents().size(), operationName);
			SecuredSending(output);
			SecuredReceiving(input);
			System.out.printf("\n*****\tExpected_#_(%d)\tActual_#_(%d)\t<---\t%s_PARAMETERS_EXCHANGE_COMPLETED\t<---\t*****\n", expectedR, rep.getObjContents().size(), operationName);
		}
		catch(Exception exception)
		{
			System.err.println("Error: " + exception.getMessage());
			exception.printStackTrace(System.err);
		}
	}
}