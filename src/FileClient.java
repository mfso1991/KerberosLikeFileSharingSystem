
/******************************************************************************************************************************************************/
/************************************************************* Art_OF_You Zhou ************************************************************************/
/******************************************************************************************************************************************************/

import java.io.*;
import java.math.*;
import java.util.*;
import javax.crypto.*;
import java.security.*;
import javax.crypto.spec.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class FileClient extends Client
{	
	private SecureRandom random = new SecureRandom();
	private PublicKey publicKey = null;
	private SecretKeySpec K_fi = null;
	private Envelope rep = null;
	private Envelope req = null;
	private Key  K_cf = null; 
	private Mac Hmac = null;
	private long R_cf = 199188; //No Worry, it will be randomized. 
	
	public boolean handShaking(byte[] keyForHMAC, Key AES128, PublicKey groupServer_publicKey, long randSerialID, UserToken token)
	{
		Security.addProvider(new BouncyCastleProvider());
		try
		{
			/*
			 *	Keys Filed
			 */
				K_fi = new SecretKeySpec(keyForHMAC, "HmacSHA1");
				K_cf = AES128;
				R_cf = randSerialID;

			/*
			 *	FileClient-FileServer HandShaking Starts
			 */
				req = new Envelope("HANDSHAKING");
				
				
						Cipher RSA_Cipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA256AndMGF1Padding", "BC");
						RSA_Cipher.init(Cipher.ENCRYPT_MODE, publicKey);
						req.addObject(RSA_Cipher.doFinal(keyForHMAC));
						req.addObject(RSA_Cipher.doFinal(AES128.getEncoded()));
					/*
					 *	Envelope({K_fi}K_f || {K_cf}K_f)
					 */
						System.out.println("***** Keys to be sent have been packed cryptographically *****");
				
				
						Envelope authInfoEnvelope = new Envelope("AUTHINFO");
						authInfoEnvelope.addObject(R_cf);
						authInfoEnvelope.addObject(new UserToken(token));
						byte[] IV = new byte[16];
						random.nextBytes(IV);
						Cipher AES_Cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
						AES_Cipher.init(Cipher.ENCRYPT_MODE, K_cf, new IvParameterSpec(IV));
						SealedObject sealedAuthInfoEnv = new SealedObject(authInfoEnvelope, AES_Cipher);
						req.addObject(sealedAuthInfoEnv);
					/*
					 *	Envelope({K_fi}K_f || {K_cf}K_f || {R_cf || UserToken}K_cf)
					 */
						System.out.println("***** Info for user authentication has been packed cryptographically *****");

						
						Hmac = Mac.getInstance("HmacSHA1");
						Hmac.init(K_fi);
						byte[] hmac_1 = Hmac.doFinal(K_fi.getEncoded());
						byte[] hmac_2 = Hmac.doFinal(K_cf.getEncoded());
						byte[] hmac_3 = Hmac.doFinal(Long.toString(R_cf).getBytes("UTF-8"));
						req.addObject((new String(hmac_1) + new String(hmac_2) + new String(hmac_3)));
					/*
					 *	Envelope({K_fi}K_f || {K_cf}K_f || {R_cf || UserToken}K_cf || {{HMACSHA1(K_fi, {K_fi}) || HMACSHA1(K_fi, {K_cf}) || HMACSHA1(K_fi, {R_cf})} = _HMAC_})
					 */
						System.out.println("***** HMACSHA1 VALUE GENERATED *****");

						
						req.addObject(IV);
					/*
					 *	Envelope({K_fi}K_f || {K_cf}K_f || Envelope({R_cf || UserToken}K_cf) || _HMAC_ || {IV})
					 */
						System.out.println("***** AES IV INSERTED *****");
						
						
						req.addObject(groupServer_publicKey);
					/*
					 *	Envelope({K_fi}K_f || {K_cf}K_f || Envelope({R_cf || UserToken}K_cf) || _HMAC_ || {IV} || {K_g})
					 */
						System.out.println("***** GroupServer Public Key INSERTED *****");

						
								output.writeObject(req);		
							/*
							 *	Upon Receiving, we expect : <--- Envelope({R_cf++}K_cf || HMACSHA1(K_fi, {{R_cf++}K_cf}) || {IV}) <---
							 */
								rep = (Envelope)input.readObject();

								
						if(rep.getMessage().equals("FAIL"))
						{
							System.out.println((String)rep.getObjContents().get(0));
							return false;
						}
						return (R_cf++ == (long)rep.getObjContents().get(0));
						
					/*
					 *	FileClient-FileServer HandShaking Completed
					 */
		}
		catch(Exception exception)
		{
			System.err.println(exception.getMessage());
			exception.printStackTrace(System.err);
		}
		return false;
	}

	@SuppressWarnings("unchecked")
	public ArrayList<String> listFiles(UserToken token) 
	{
		try
		{
			req = new Envelope("LISTFILES");
			req.addObject(new UserToken(token));
			
				/*
				 *	---> {UserToken || R_cf++}K_cf || HMACSHA1(K_fi, {{UserToken || R_cf++}K_cf}) || IV --->
				 */
					CommuThruSecuredChannel(1, 2, "LISTFILES");
				/*
				 *	<--- {ListOfAccessibleFiles || R_cf++}K_cf || HMACSHA1(K_fi, {{ListOfAccessibleFiles || R_cf++}K_cf}) || IV <---
				 */
				
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
		}
		return new ArrayList<String>();
	}
	public boolean delete(String filename, UserToken token) 
	{	
	    try 
		{
			req = new Envelope("DELETEFILE");
			req.addObject(new UserToken(token));			
			req.addObject(filename);
			
				/*
				 *	---> {UserToken || filename || R_cf++}K_cf || HMACSHA1(K_fi, {{UserToken || filename || R_cf++}K_cf}) || IV --->
				 */				
					CommuThruSecuredChannel(2, 1, "DELETEFILE");
				/*
				 *	<--- {R_cf++}K_cf || HMACSHA1(K_fi, {{R_cf++}K_cf}) || IV <---
				 */
				
			if(rep.getMessage().equals("FAIL"))
			{
				System.out.println((String)rep.getObjContents().get(0));
				return false;
			}
			return true;
		} 
		catch (Exception exception) 
		{
			System.err.println("Error: " + exception.getMessage());
			exception.printStackTrace();
		} 
		return false;
	}
	public boolean upload(String sourceFile, String fileDestination, Envelope env, String groupname, UserToken token) 
	{
		try
		{ 
			File file = new File(sourceFile);
			if(!file.exists())
			{
				System.out.println("###### ERROR : FILE_DOES_NOT_EXIST ######");
				return false;
			}
			req = new Envelope("UPLOADFILE");
			req.addObject(new UserToken(token));
			req.addObject(fileDestination);
			req.addObject(groupname);
			req.addObject(env);
			
				/*
				 *	 --->
				 *	{UserToken || fileDestination || groupname || Envelope(K_file, IV, File_version) || R_cf++}K_cf || 
				 *	 HMACSHA1(K_fi, {{UserToken || fileDestination || groupname || Envelope(K_file, IV, File_version) || R_cf++}K_cf}) || IV
				 *	 --->
				 */
					CommuThruSecuredChannel(4, 1, "UPLOADFILE");
				/*
				 *	 <--- {R_cf++}K_cf || HMACSHA1(K_fi, {{R_cf++}K_cf}) || IV <---
				 */
			
			if(rep.getMessage().equals("FAIL"))
			{
				System.out.println((String)rep.getObjContents().get(0));
				return false;
			}
			
			FileInputStream fis = new FileInputStream(file);
			do 
			{
				byte[] buf = new byte[4096];
				int n = fis.read(buf);
				if (n < 0) 
				{
					System.out.println("###### ERROR : READING_FILE ######");
					return false;
				}
				req = new Envelope("FEEDINGBYTES");
				req.addObject(new UserToken(token));
				req.addObject(buf);
				req.addObject(new Integer(n));
				
					/*
					 *	---> {UserToken || byte[] || n || R_cf++}K_cf || HMACSHA1(K_fi, {{UserToken || byte[] || n || R_cf}K_cf}) || IV --->
					 */
						CommuThruSecuredChannel(3, 1, "FEEDINGBYTES");
					/*
					 *	<--- {R_cf++}K_cf || HMACSHA1(K_fi, {R_cf++}K_cf) || IV <---
					 */		
					 
				if(rep.getMessage().equals("FAIL"))
				{
					System.out.println((String)rep.getObjContents().get(0));
					return false;
				}					 
			}
			while (fis.available() > 0);		 
					 
			req = new Envelope("END_OF_FILE");
			req.addObject(new UserToken(token));
				
			    /*
				 *	---> {UserToken || R_cf++}K_cf || HMACSHA1(K_fi, {{UserToken || R_cf++}K_cf}) || IV --->
				 */		
					CommuThruSecuredChannel(1, 1, "ADDTOFILEPRIORITYQUEUE");
				/*
				 *	<--- {R_cf++}K_cf || HMACSHA1(K_fi, {R_cf++}K_cf) || IV <---
				 */	
				 
			if(rep.getMessage().equals("FAIL"))
			{
				System.out.println((String)rep.getObjContents().get(0));
				return false;
			}	
			return (rep.getMessage().equals("OK"));
		}
		catch(Exception exception)
		{
			System.err.println("Error: " + exception.getMessage());
			exception.printStackTrace(System.err);
		}
		return false;
	}
	
	public String getInsecureFile(UserToken token)
	{
		try
		{
			req = new Envelope("GETENDF");
			req.addObject(new UserToken(token));	
			
			CommuThruSecuredChannel(1, 2, "GETENDF");
			
			if(rep.getMessage().equals("FAIL"))
			{
				System.out.println((String)rep.getObjContents().get(0));
				return "";
			}
			return (String)rep.getObjContents().get(0);
		}
		catch (Exception exception)
		{
			System.err.println("Error: " + exception.getMessage());
			exception.printStackTrace();
		}
		return "";
	}
	public boolean download(String sourceFile, String fileDestination, Envelope env, UserToken token) 
	{
		try 
		{
			File file = new File(fileDestination);
			if(file.exists())
			{
				System.out.println("###### ERROR : FILE_ALREADY_EXISTED ######");
				return false;	
			}
			req = new Envelope("DOWNLOADFILE");
			req.addObject(new UserToken(token));
			req.addObject(sourceFile);
			req.addObject(env);				     

				/*
				 *	 --->
				 *	{UserToken || sourceFile || Envelope(K_file, IV, File_version) || R_cf++}K_cf || 
				 *	 HMACSHA1(K_fi, {{UserToken || sourceFile || Envelope(K_file, IV, File_version) || R_cf++}K_cf}) || IV
				 *	 --->
				 */
					CommuThruSecuredChannel(3, 3, "DOWNLOADFILE");
				/*
				 *	 <--- {byte[] || n || R_cf++}K_cf || HMACSHA1(K_fi, {{byte[] || n || R_cf++}K_cf}) || IV <---
				 */	
				 
			if(rep.getMessage().equals("FAIL"))
			{
				System.out.println((String)rep.getObjContents().get(0));
				return false;
			}
			
			file.createNewFile();
			FileOutputStream fos = new FileOutputStream(file);
			while(rep.getMessage().equals("WRITINGBYTES")) 
			{ 
				fos.write((byte[])rep.getObjContents().get(0), 0, (Integer)rep.getObjContents().get(1));
				req = new Envelope("ASKINGFORBYTES");
				req.addObject(new UserToken(token));
				
					/*
					 *	---> {UserToken || R_cf++}K_cf || HMACSHA1(K_fi, {{UserToken || R_cf++}K_cf}) || IV --->
					 */		
						CommuThruSecuredChannel(1, 3, "READINGBYTES");
					/*
					 *	<--- {byte[] || n || R_cf++}K_cf || HMACSHA1(K_fi, {{byte[] || n || R_cf++}K_cf}) || IV <---
					 */
					 
				if(rep.getMessage().equals("FAIL"))
				{
					System.out.println((String)rep.getObjContents().get(0));
					return false;
				}
			}		
			fos.close();
			return (rep.getMessage().equals("END_OF_FILE"));
		} 
		catch (Exception exception)
		{
			System.err.println("Error: " + exception.getMessage());
			exception.printStackTrace();
		}
		return false;
	}
	public boolean deleteAssociatedFiles(String groupname, UserToken token)
	{
		try
		{
			req = new Envelope("DELETEASSOCIATEDFILES");
			req.addObject(new UserToken(token));
			req.addObject(groupname);
			
			    /*
				 *	---> {UserToken || groupname || R_cf++}K_cf || HMACSHA1(K_fi, {{UserToken || groupname || R_cf++}K_cf}) || IV --->
				 */		
					CommuThruSecuredChannel(2, 1, "DELETEASSOCIATEDFILES");
				/*
				 *	<--- {R_cf++}K_cf || HMACSHA1(K_fi, {R_cf++}K_cf) || IV <---
				 */		
			
			if(rep.getMessage().equals("FAIL"))
			{
				System.out.println((String)rep.getObjContents().get(0));
				return false;
			}
			return true;
		}
		catch (Exception exception)
		{
			System.err.println("Error: " + exception.getMessage());
			exception.printStackTrace();
		}
		return false;
	}
	
	public String getFileGroup(String filename, UserToken token)
	{
		try
		{
			req = new Envelope("GETFILEGROUP");
			req.addObject(new UserToken(token));
			req.addObject(filename);
			
			    /*
				 *	---> {UserToken || filename || R_cf++}K_cf || HMACSHA1(K_fi, {{UserToken || groupname || R_cf++}K_cf}) || IV --->
				 */		
					CommuThruSecuredChannel(2, 2, "GETFILEGROUP");
				/*
				 *	<--- {groupname || R_cf++}K_cf || HMACSHA1(K_fi, {{groupname || R_cf++}K_cf}) || IV <---
				 */		
			
			if(rep.getMessage().equals("FAIL"))
			{
				System.out.println((String)rep.getObjContents().get(0));
				return null;
			}
			return (String)rep.getObjContents().get(0);
		}
		catch(Exception exception)
		{
			System.err.println("Error: " + exception.getMessage());
			exception.printStackTrace();
		}	
		return null;
	}
	
	public PublicKey fetchPublicKey()
	{
		try 
		{
			req = new Envelope("GETFPUB");
			output.writeObject(req);
			rep = (Envelope)input.readObject();
			publicKey = (PublicKey)rep.getObjContents().get(0);
			return publicKey;
		}
		catch(Exception exception) 
		{
			System.err.println("Error: " + exception.getMessage());
			exception.printStackTrace(System.err);
		}
		return null;
	}

		/************************************************************************************************************************************************/
		/*******************************************************	  KERNEL METHODS 	 ****************************************************************/
		/************************************************************************************************************************************************/
		
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
				req.addObject(R_cf++);
				Cipher AES_Cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
				byte[] IV = new byte[16];
				random.nextBytes(IV);
				AES_Cipher.init(Cipher.ENCRYPT_MODE, K_cf, new IvParameterSpec(IV));
				SealedObject sealedObject = new SealedObject(req, AES_Cipher);
				Envelope fileClientRequest = new Envelope("REQ");
				fileClientRequest.addObject(sealedObject);
				fileClientRequest.addObject(new String(Hmac.doFinal(serialize(sealedObject))));
				fileClientRequest.addObject(IV);
				output.writeObject(fileClientRequest);
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
				Envelope fileServerReply = (Envelope)input.readObject();
				SealedObject sealedObject = (SealedObject)fileServerReply.getObjContents().get(0);
				if(!new String(Hmac.doFinal(serialize(sealedObject))).equals((String)fileServerReply.getObjContents().get(1)))
				{
					rep = new Envelope("FAIL");
					rep.addObject("###### FILECLIENT ERROR : GARBLED_MESSAGE ######");
				}
				else
				{
					byte[] IV = (byte[])fileServerReply.getObjContents().get(2);
					Cipher AES_Cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
					AES_Cipher.init(Cipher.DECRYPT_MODE, K_cf, new IvParameterSpec(IV));
					rep = (Envelope)sealedObject.getObject(AES_Cipher);
					if(R_cf++ != (long)rep.getObjContents().get(rep.getObjContents().size() - 1))
					{
						rep = new Envelope("FAIL");
						rep.addObject("###### FILECLIENT ERROR : REPLAY/REORDER_ATTACK ######");
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
				//System.out.printf("\nExpected_#_(%d) Actual_#_(%d)   %s_PARAMETERS_EXCHANGE_STARTS  --->\n", expectedS, req.getObjContents().size(), operationName);
				SecuredSending(output);
				SecuredReceiving(input);
				//System.out.printf("\nExpected_#_(%d) Actual_#_(%d) %s_PARAMETERS_EXCHANGE_COMPLETED <---\n", expectedR, rep.getObjContents().size(), operationName);
			}
			catch(Exception exception)
			{
				System.err.println("Error: " + exception.getMessage());
				exception.printStackTrace(System.err);
			}
		}
}