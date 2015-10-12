
import java.io.*;
import java.util.*;
import java.net.*;
import java.security.*;
import java.security.spec.*;
import java.math.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class GroupServer extends Server 
{
	public static final int SERVER_PORT = 8765;
	public Arbitrator arbitrator;
	public KeyPair RSA_keypair = null;
	
	public GroupServer() 
	{
		super(SERVER_PORT, "ALPHA");
	}

	public GroupServer(int _port) 
	{
		super(_port, "ALPHA");
	}

	public void start() 
	{
		Security.addProvider(new BouncyCastleProvider()); 
		if(RSA_keypair == null)
		{
			try
			{
				KeyPairGenerator RSA_gen = KeyPairGenerator.getInstance("RSA");
				RSA_gen.initialize(2048);
				RSA_keypair = RSA_gen.generateKeyPair();
			}
			catch (Exception exception) 
			{
				System.out.println("Error: " + exception.getMessage());
				exception.printStackTrace();
			}
		}
		
		String userFile = "User-Group.bin";
		Scanner console = new Scanner(System.in);
		ObjectInputStream userStream;
		ObjectInputStream groupStream;

		Runtime runtime = Runtime.getRuntime();
		runtime.addShutdownHook(new ShutDownListener(this));
		
		try
		{
			FileInputStream fis = new FileInputStream(userFile);
			userStream = new ObjectInputStream(fis);
			arbitrator = (Arbitrator)userStream.readObject();
		}
		catch(FileNotFoundException exception)
		{
			System.out.println("User-Group File Does Not Exist. Creating User-Group File...");
			System.out.println("No users currently exist. Your account will be the administrator.");
			System.out.print("Enter your user name: ");
			String username = console.next();
			arbitrator = new Arbitrator();
			try
			{
				MessageDigest SHA256_digest = MessageDigest.getInstance("SHA256");
				SHA256_digest.update(username.getBytes("UTF-8"));
				arbitrator.createUser(username, SHA256_digest.digest());
				Signature signer = Signature.getInstance("SHA256withRSA");
				signer.initSign(RSA_keypair.getPrivate());
				signer.update("ADMIN".getBytes("UTF-8"));
				arbitrator.createGroup(username, new String(signer.sign(), "UTF-8"));
			}
			catch(Exception exceptione)
			{
				System.out.println("Error: " + exception.getMessage());
				exception.printStackTrace();
			}
		}
		catch(IOException exception)
		{
			System.out.println("Error reading from User-Group file");
			System.exit(-1);
		}
		catch(ClassNotFoundException exception)
		{
			System.out.println("Error reading from User-Group file");
			System.exit(-1);
		}

		AutoSave aSave = new AutoSave(this);
		aSave.setDaemon(true);
		aSave.start();

		try
		{

			final ServerSocket serverSock = new ServerSocket(port);
			Socket sock = null;
			GroupThread thread = null;
			while(true)
			{
				sock = serverSock.accept();
				thread = new GroupThread(sock, this, RSA_keypair.getPrivate(), RSA_keypair.getPublic());
				thread.start();
			}
		}
		catch(Exception exception)
		{
			System.err.println("Error: " + exception.getMessage());
			exception.printStackTrace(System.err);
		}
	}
}

	class ShutDownListener extends Thread
	{
		public GroupServer my_gs;

		public ShutDownListener (GroupServer _gs) 
		{
			my_gs = _gs;
		}

		public void run()
		{
			System.out.println("Shutting down server");
			ObjectOutputStream outStream;
			try
			{
				outStream = new ObjectOutputStream(new FileOutputStream("User-Group.bin"));
				outStream.writeObject(my_gs.arbitrator);
			}
			catch(Exception exception)
			{
				System.err.println("Error: " + exception.getMessage());
				exception.printStackTrace(System.err);
			}
		}
	}

	class AutoSave extends Thread
	{
		public GroupServer my_gs;

		public AutoSave (GroupServer _gs) 
		{
			my_gs = _gs;
		}

		public void run()
		{
			do
			{
				try
				{
					Thread.sleep(300000); //Save group and user lists every 5 minutes
					System.out.println("Auto-save group and user information...");
					ObjectOutputStream outStream;
					try
					{
						outStream = new ObjectOutputStream(new FileOutputStream("User-Group.bin"));
						outStream.writeObject(my_gs.arbitrator);
					}
					catch(Exception exception)
					{
						System.err.println("Error: " + exception.getMessage());
						exception.printStackTrace(System.err);
					}

				}
				catch(Exception exception)
				{
					System.out.println("Auto-save Interrupted");
				}
			} 
			while(true);
		}
	}