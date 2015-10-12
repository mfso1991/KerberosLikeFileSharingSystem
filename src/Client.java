import java.net.Socket;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

public abstract class Client 
{
	protected Socket sock;
	protected ObjectOutputStream output;
	protected ObjectInputStream input;

	public boolean connect(final String server, final int port) 
	{
		System.out.println("Attempting to connect");
		
		try
		{
			sock = new Socket(server, port);
			output = new ObjectOutputStream(sock.getOutputStream());
			input = new ObjectInputStream(sock.getInputStream());
					
			if(sock == null || output == null || input == null)
			{
				System.out.println("Unable to connect.");
				if(sock != null)
					sock.close();
				return false;
			}
		}
		catch(Exception exception)
		{
			System.err.println("Error: " + exception.getMessage());
			exception.printStackTrace(System.err);
		}

		System.out.println("Connected to " + server + ":" + port);
		return true;
	}

	public boolean isConnected() 
	{
		if (sock == null || !sock.isConnected()) return false;
		else return true;
	}

	public void disconnect()	 
	{
		if (isConnected()) 
		{
			try
			{
				Envelope message = new Envelope("DISCONNECT");
				output.writeObject(message);
			}
			catch(Exception exception)
			{
				System.err.println("Error: " + exception.getMessage());
				exception.printStackTrace(System.err);
			}
		}
	}
}
