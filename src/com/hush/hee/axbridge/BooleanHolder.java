package com.hush.hee.axbridge;

public class BooleanHolder
{
	private boolean bool;
	
	public BooleanHolder()
	{
	}
	
	public BooleanHolder(boolean bool)
	{
		this.setBoolean(bool);
	}
	
	public void setBoolean(boolean bool)
	{
		this.bool = bool;
	}
	
	public Boolean getBoolean()
	{
		return bool;
	}
}