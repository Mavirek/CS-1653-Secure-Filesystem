import java.util.*;
import java.security.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.*;

public class GroupKeys implements java.io.Serializable
{
	private Hashtable<String, ArrayList<SecretKey>> gkList = new Hashtable<String, ArrayList<SecretKey>>();
	
	public synchronized void addGroup(String group, SecretKey key)
	{
		ArrayList<SecretKey> keyList = new ArrayList<SecretKey>();
		keyList.add(key);
		gkList.put(group,keyList);
	}
	
	public synchronized void removeGroup(String group)
	{
		gkList.remove(group);
	}
	
	public synchronized void addKey(String group, SecretKey key)
	{
		ArrayList<SecretKey> keyList = gkList.get(group);
		keyList.add(key);
		gkList.put(group, keyList);
	}
	
	public synchronized ArrayList<SecretKey> getKeys(String group)
	{
		return gkList.get(group);
	}
	
}