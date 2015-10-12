

/*
 *	The most recent modifier : You Zhou	
 */

import java.io.*;
import java.util.*;
import java.net.*;
import java.security.*;
import java.security.spec.*;
import java.math.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class FileServer extends Server 
{
	
	public static final int SERVER_PORT = 4321;
	public static FilePriorityQueue filePriorityQueue;
	public KeyPair RSA_keypair;
	
	public FileServer() 
	{
		super(SERVER_PORT, "FilePile");
	}

	public FileServer(int _port) 
	{
		super(_port, "FilePile");
	}
	
	public void start() 
	{
		Security.addProvider(new BouncyCastleProvider());
		if(RSA_keypair == null)
		{
			try
			{
				KeyPairGenerator RSA_Gen = KeyPairGenerator.getInstance("RSA");
				RSA_Gen.initialize(2048);
				RSA_keypair = RSA_Gen.generateKeyPair();
			}
			catch(Exception exception)
			{
				System.out.println("Error: " + exception.getMessage());
				exception.printStackTrace();
			}
		}

		String fileFile = "filePriorityQueue.bin";
		ObjectInputStream fileStream;
		
		Runtime runtime = Runtime.getRuntime();
		Thread catchExit = new Thread(new ShutDownListenerFS());
		runtime.addShutdownHook(catchExit);
		
		try
		{
			FileInputStream fis = new FileInputStream(fileFile);
			fileStream = new ObjectInputStream(fis);
			filePriorityQueue = (FilePriorityQueue)fileStream.readObject();
		}
		catch(FileNotFoundException exception)
		{
			System.out.println("filePriorityQueue.bin Does Not Exist. Creating filePriorityQueue...");	
			filePriorityQueue = new FilePriorityQueue();
		}
		catch(IOException exception)
		{
			System.out.println("Error reading from filePriorityQueue file");
			System.exit(-1);
		}
		catch(ClassNotFoundException exception)
		{
			System.out.println("Error reading from filePriorityQueue file");
			System.exit(-1);
		}
		
		File file = new File("shared_files");
		if (file.mkdir()) 
			System.out.println("Created new shared_files directory");
		else if (file.exists())
			System.out.println("Found shared_files directory");
		else 
			System.out.println("Error creating shared_files directory");				 
		
		AutoSaveFS aSave = new AutoSaveFS();
		aSave.setDaemon(true);
		aSave.start();

		boolean running = true;		
		try
		{	
			final ServerSocket serverSock = new ServerSocket(port);
			System.out.printf("%s up and running\n", this.getClass().getName());
			Socket sock = null;
			Thread thread = null;
			while(running)
			{
				sock = serverSock.accept();
				thread = new FileThread(sock, RSA_keypair.getPrivate(), RSA_keypair.getPublic());
				thread.start();
			}
			System.out.printf("%s shut down\n", this.getClass().getName());
		}
		catch(Exception exception)
		{
			System.err.println("Error: " + exception.getMessage());
			exception.printStackTrace(System.err);
		}
	}
}

	class ShutDownListenerFS implements Runnable
	{
		public void run()
		{
			System.out.println("Shutting down server");
			ObjectOutputStream outStream;

			try
			{
				outStream = new ObjectOutputStream(new FileOutputStream("filePriorityQueue.bin"));
				outStream.writeObject(FileServer.filePriorityQueue);
			}
			catch(Exception exception)
			{
				System.err.println("Error: " + exception.getMessage());
				exception.printStackTrace(System.err);
			}
		}
	}

	class AutoSaveFS extends Thread
	{
		public void run()
		{
			do
			{
				try
				{
					Thread.sleep(300000);
					System.out.println("Autosave file list...");
					ObjectOutputStream outStream;
					try
					{
						outStream = new ObjectOutputStream(new FileOutputStream("filePriorityQueue.bin"));
						outStream.writeObject(FileServer.filePriorityQueue);
					}
					catch(Exception exception)
					{
						System.err.println("Error: " + exception.getMessage());
						exception.printStackTrace(System.err);
					}

				}
				catch(Exception exception)
				{
					System.out.println("Autosave Interrupted");
				}
			}while(true);
		}
	}