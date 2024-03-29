import java.util.ArrayList;


public class Envelope implements java.io.Serializable {

	/**
	 *
	 */
	private static final long serialVersionUID = -7726335089122193103L;
	private String msg;
	private ArrayList<Object> objContents = new ArrayList<Object>();
	private String env; 
	public Envelope(String text)
	{
		msg = text;
	}

	public String getMessage()
	{
		return msg;
	}

	public ArrayList<Object> getObjContents()
	{
		return objContents;
	}

	public void addObject(Object object)
	{
		objContents.add(object);
	}
	public String toString()
	{
		if(env == null)
			return msg; 
		return env;  
	}
	public void setStringRep(String rep)
	{
		env = rep; 
	}
}
