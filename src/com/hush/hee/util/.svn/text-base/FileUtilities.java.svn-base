/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.hee.util;

import java.awt.FileDialog;
import java.awt.Frame;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

import com.hush.applet.security.Badge;
import com.hush.applet.security.Strategy;
import com.hush.util.Logger;

public class FileUtilities
{
	public static final String MS_TMP = "Temp";
	public static final String TEMP_EXT = ".tmp";
	public static final String BACKUP_EXT = ".bak";
	private String selectedFile = null;
	private String tmpDir = null;
	private File tempFile;
	private String line;
	private byte[] entireFile;
	private FileInputStream fileInputStream;
	private FileOutputStream fileOutputStream;
	private boolean deleted;
	private boolean renamed;
	private long length;

	public File createBackup(File file) throws IOException
	{
		File backupFile = getTempFile(file, BACKUP_EXT, true);
		copy(file, backupFile);
		return backupFile;
	}

	public File getTempFile(File file)
	{
		return getTempFile(file, TEMP_EXT, false);
	}

	public File getTempFile(
		final File file,
		final String ext,
		final boolean inSameDir)
	{
		Strategy strategy = Strategy.createStrategy();
		strategy.handle(new Badge()
		{
			public void invoke(Strategy strat)
			{
				File myTmpDir = getTempDir();

				if (myTmpDir == null || inSameDir)
				{
					tempFile = new File(file.getAbsolutePath() + TEMP_EXT);
				}
				else
				{
					tempFile = new File(myTmpDir, file.getName() + TEMP_EXT);
				}

				int x = 0;
				int charChop = 0;
				String tempFileName = tempFile.getAbsolutePath();

				while (tempFile.exists())
				{
					tempFileName =
						tempFileName.substring(
							0,
							tempFileName.length() - charChop);
					tempFileName = tempFileName + x;
					tempFile = new File(tempFileName);
					charChop = String.valueOf(x).length();
					x++;
				}
			}
		});

		return tempFile;
	}

	private IOException iOException0 = null;

	public synchronized void copy(File src, File dest) throws IOException
	{
		iOException0 = null;
		final File srcF = src;
		final File destF = dest;
		Strategy strategy = Strategy.createStrategy();
		strategy.handle(new Badge()
		{
			public void invoke(Strategy strat)
			{
				try
				{
					BufferedInputStream in =
						new BufferedInputStream(new FileInputStream(srcF));
					BufferedOutputStream out =
						new BufferedOutputStream(new FileOutputStream(destF));
					int read = 0;

					while ((read = in.read()) != -1)
					{
						out.write(read);
					}

					in.close();
					out.close();
				}
				catch (IOException ie)
				{
					iOException0 = ie;
				}
			}
		});

		if (iOException0 != null)
		{
			throw iOException0;
		}
	}

	private IOException iOException1 = null;

	public synchronized String getFirstLine(File src) throws IOException
	{
		iOException1 = null;
		final File srcF = src;
		Strategy strategy = Strategy.createStrategy();
		strategy.handle(new Badge()
		{
			public void invoke(Strategy strat)
			{
				try
				{
					BufferedReader in =
						new BufferedReader(new FileReader(srcF));

					while ("".equals(line = in.readLine()))
					{
					}

					in.close();
				}
				catch (IOException ie)
				{
					iOException1 = ie;
				}
			}
		});

		if (iOException1 != null)
		{
			throw iOException1;
		}

		return line;
	}

	private IOException iOException2 = null;

	public synchronized byte[] getEntireFile(File src) throws IOException
	{
		iOException2 = null;
		final File srcF = src;
		Strategy strategy = Strategy.createStrategy();
		strategy.handle(new Badge()
		{
			public void invoke(Strategy strat)
			{
				try
				{
					FileInputStream in = new FileInputStream(srcF);
					ByteArrayOutputStream out = new ByteArrayOutputStream();
					int read = 0;

					while ((read = in.read()) != -1)
					{
						out.write(read);
					}

					in.close();
					out.close();
					entireFile = out.toByteArray();
				}
				catch (IOException ie)
				{
					iOException2 = ie;
				}
			}
		});

		if (iOException2 != null)
		{
			throw iOException2;
		}

		return entireFile;
	}

	private IOException iOException3 = null;

	public synchronized void writeFile(byte[] src, File dest)
		throws IOException
	{
		iOException3 = null;
		final byte[] srcF = src;
		final File destF = dest;
		Strategy strategy = Strategy.createStrategy();
		strategy.handle(new Badge()
		{
			public void invoke(Strategy strat)
			{
				try
				{
					FileOutputStream out = new FileOutputStream(destF);
					out.write(srcF);
					out.close();
				}
				catch (IOException ie)
				{
					iOException3 = ie;
				}
			}
		});

		if (iOException3 != null)
		{
			throw iOException3;
		}
	}

	public File getTempDir()
	{
		tmpDir = null;

		Strategy strategy = Strategy.createStrategy();
		strategy.handle(new Badge()
		{
			public void invoke(Strategy strat)
			{
				tmpDir = System.getProperty("java.io.tmp");

				if (tmpDir == null)
				{
					try
					{
						// Use reflection here so we can compile without the Microsoft classes
						Class specialFolder =
							Class.forName("com.ms.wfc.app.SpecialFolder");
						Field tempDirField =
							specialFolder.getDeclaredField("INTERNET_CACHE");
						Integer tmpDirInt = (Integer) tempDirField.get(null);
						Class specialFolderPath =
							Class.forName("com.ms.wfc.app.SystemInformation");
						Method specialFolderPathMethod =
							specialFolderPath.getDeclaredMethod(
								"getSpecialFolderPath",
								new Class[] { java.lang.Integer.TYPE });
						tmpDir =
							(String) specialFolderPathMethod.invoke(
								null,
								new Object[] { tmpDirInt });
					}
					catch (Exception e)
					{
						Logger.logThrowable(this, Logger.ERROR, "Error getting temp dir", e);
						tmpDir = null;
					}
				}
			}
		});

		return (tmpDir == null) ? null : new File(tmpDir);
	}

	private FileNotFoundException fileNotFoundException0 = null;

	public synchronized FileInputStream getFileInputStream(File file)
		throws FileNotFoundException
	{
		fileNotFoundException0 = null;
		final File fileF = file;
		Strategy strategy = Strategy.createStrategy();
		strategy.handle(new Badge()
		{
			public void invoke(Strategy strat)
			{
				try
				{
					fileInputStream = new FileInputStream(fileF);
				}
				catch (FileNotFoundException f)
				{
					fileNotFoundException0 = f;
				}
			}
		});

		if (fileNotFoundException0 != null)
		{
			throw fileNotFoundException0;
		}

		return fileInputStream;
	}

	private RuntimeException runtimeException4 = null;
	private IOException iOException4 = null;
	private FileNotFoundException fileNotFoundException1 = null;
	
	public synchronized FileOutputStream getFileOutputStream(File file)
		throws FileNotFoundException, IOException
	{
		fileNotFoundException1 = null;
		iOException4 = null;
		runtimeException4 = null;
		final File fileF = file;
		Strategy strategy = Strategy.createStrategy();
		strategy.handle(new Badge()
		{
			public void invoke(Strategy strat)
			{
				try
				{
					fileOutputStream = new FileOutputStream(fileF);
				}
				catch (FileNotFoundException f)
				{
					fileNotFoundException1 = f;
				}
				catch (IOException i)
				{
					iOException4 = i;
				}
				catch (RuntimeException i)
				{
					runtimeException4 = i;
				}
			}
		});

		if (fileNotFoundException1 != null)
		{
			throw fileNotFoundException1;
		}

		if (iOException4 != null)
		{
			throw iOException4;
		}
		
		if (runtimeException4 != null)
		{
			throw runtimeException4;
		}

		return fileOutputStream;
	}

	public boolean delete(File file)
	{
		final File fileF = file;
		Strategy strategy = Strategy.createStrategy();
		strategy.handle(new Badge()
		{
			public void invoke(Strategy strat)
			{
				deleted = fileF.delete();
			}
		});

		return deleted;
	}

	public boolean rename(File src, File dest)
	{
		final File srcF = src;
		final File destF = dest;
		Strategy strategy = Strategy.createStrategy();
		strategy.handle(new Badge()
		{
			public void invoke(Strategy strat)
			{
				renamed = srcF.renameTo(destF);
			}
		});
		return renamed;
	}

	public long length(File src)
	{
		final File srcF = src;
		Strategy strategy = Strategy.createStrategy();
		strategy.handle(new Badge()
		{
			public void invoke(Strategy strat)
			{
				length = srcF.length();
			}
		});
		return length;
	}

	public String selectFile(
		final String filename,
		final String prompt,
		final int mode)
	{
		Strategy strategy = Strategy.createStrategy();
		strategy.handle(new Badge()
		{
			public void invoke(Strategy strat)
			{
				// Create a File Save dialog defaulting to the attachment name.
				FileDialog dialog = new FileDialog(new Frame(), prompt, mode);
				dialog.setFile(filename);
				dialog.show();

				// Check for a valid file and directory.
				if ((dialog.getFile() != null)
					&& (dialog.getDirectory() != null))
				{
					// Save the attachment to the local hard-drive.
					File file =
						new File(dialog.getDirectory(), dialog.getFile());
					selectedFile = file.getPath();
				}

				dialog.hide();
			}
		});

		return selectedFile;
	}

}