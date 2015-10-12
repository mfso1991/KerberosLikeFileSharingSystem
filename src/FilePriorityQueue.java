

import java.util.*;

public class FilePriorityQueue implements java.io.Serializable 
{
	private static final long serialVersionUID = -8911161283900260136L;
	private PriorityQueue<SharedFile> filePQ = null;
	
	public FilePriorityQueue()
	{
		filePQ = new PriorityQueue<SharedFile>();
	}
	
	public synchronized void addFile(String owner, String group, String path, long curTime)
	{
		SharedFile newFile = new SharedFile(owner, group, path, curTime);
		filePQ.add(newFile);
	}
	
	public synchronized boolean removeFile(SharedFile sf)
	{
		return filePQ.remove(sf);
	}
	
	public synchronized boolean isEmpty()
	{
		return filePQ.isEmpty();
	}
	
	public synchronized SharedFile peek()
	{
		Iterator<SharedFile> iter = this.getFiles();
		while(iter.hasNext())
			System.out.println("SharedFile : " + iter.next().getPath());
		return filePQ.peek();
	}
	
	public synchronized boolean checkFile(SharedFile sf)
	{
		return filePQ.contains(sf);
	}
	
	public synchronized Iterator<SharedFile> getFiles()
	{
		return filePQ.iterator();
	}
	
	public synchronized SharedFile getFile(SharedFile sf)
	{
		Iterator<SharedFile> iter = filePQ.iterator();
		SharedFile rt = null;
		while(iter.hasNext())
			if((rt = new SharedFile(iter.next())).equals(sf))
				return rt;
		return null;
	}
}	
