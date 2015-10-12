
public class SharedFile implements java.io.Serializable, Comparable<SharedFile> 
{
	private static final long serialVersionUID = -6699986336399821598L;
	private String group;
	private String path;
	private String owner;
	private long createdTime;
	private long count;
	
	public SharedFile(String _owner, String _group, String _path, long curTime) 
	{
		group = _group;
		owner = _owner;
		path = _path;
		count = 0;
		createdTime = curTime;
	}
	
	public SharedFile(String _path)
	{
		path = _path;
	}
	
	public SharedFile(SharedFile sf)
	{
		path = sf.getPath();
		group = sf.getGroup();
		owner = sf.getOwner();
		path = sf.getPath();
		count = sf.getCount();
		createdTime = sf.getTime();
	}
	
	public long getCount()
	{
		return count;
	}
	
	public long getTime()
	{
		return createdTime;
	}
	
	public long getPriority()
	{
		return ((new java.util.Date()).getTime()/1000 - createdTime)*count;
	}
	
	public void addCount()
	{
		count += 10;
	}
	
	public String getPath()
	{
		return path;
	}
	
	public String getOwner()
	{
		return owner;
	}
	
	public String getGroup() 
	{
		return group;
	}
	
	@Override
	public int compareTo(SharedFile rhs) 
	{
		if (path.equals(rhs.getPath()))
			return 0;
		if(rhs.getPriority() - this.getPriority() < 0)
			return -1;
		return 1;
	}
	
	@Override
	public boolean equals(Object obj)
	{
		if(obj instanceof SharedFile)
		{
			SharedFile sf = (SharedFile) obj;
			if(path.equals(sf.getPath()))
				return true;
		}
		return false;
	}
}	
