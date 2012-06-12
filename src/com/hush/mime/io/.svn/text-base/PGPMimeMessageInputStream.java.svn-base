/**
 * Decrypts raw Mime based message while data is read.
 */
package com.hush.mime.io;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PushbackInputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Vector;

import com.hush.pgp.Key;
import com.hush.pgp.Keyring;
import com.hush.pgp.io.ArmorInputStream;
import com.hush.pgp.io.PgpMessageInputStream;
import com.hush.util.Logger;
import com.hush.util.UnrecoverableKeyException;

/**
 * @author sean
 *
 */
public class PGPMimeMessageInputStream extends InputStream {
	private static final int MAX_LINE_LENGTH = 180;
	private static final int MAX_LINES = 10;
	private static final int MAX_MIME_LINE_LENGTH = 78;
	private static final byte[] CONTENT_TRANSFER_ENCODING = "Content-Transfer-Encoding".getBytes();
	private static final byte[] CLRF = "\r\n".getBytes();

	private PushbackInputStream in = null;
	private final ByteBuffer buffer;
	private PgpMessageInputStream pgpis = null;
	private Vector passwords = new Vector();
	private Vector secretKeys = new Vector();
	private Vector keyrings = new Vector();
	private boolean insideAttachment = false;
	
	/**
	 * @param in
	 */
	public PGPMimeMessageInputStream(InputStream in) {
		this.in = new PushbackInputStream(in, MAX_LINE_LENGTH);
		this.buffer = ByteBuffer.allocate(MAX_LINE_LENGTH * MAX_LINES);
		this.buffer.flip();
	}

	@Override
	public int read() throws IOException {
		byte[] buffer = new byte[1];
		int count = read(buffer);
		if (count <= 0){
			return -1;
		}
		
		return buffer[0];
	}

	@Override
	public int read(byte[] b) throws IOException {
		return read(b, 0, b.length);
	}

	@Override
	public int read(byte[] b, int off, int len) throws IOException {
		if (len == 0) {
			return 0;
		}
		// Transfers what we have in the byte buffer if we are not within a pgp block
		int pos = 0;
		while (pos < len) {
			if (this.pgpis == null) {
				while (this.buffer.hasRemaining() && pos < len) {
					b[off + pos] = this.buffer.get();
					pos++;
				}
				// Is there more still to read
				if(pos < len) {
					// We need more and clear the buffer
					this.buffer.clear();
					if (readMore() <= 0 && this.pgpis == null) {
						// We have reached the end
						return pos == 0 ? -1 : pos;
					}
				}
			} else {
				// We are inside of a pgp block
				//TODO SEAN: I must read the data and break it up if we are busy with attachments into lines of 78, but maybe not
				//ATTACHments must be converted to base 64!!!!
				
				int read = this.pgpis.read(b, off + pos, len - pos);
				if (read <= 0) {
					this.pgpis.close();
					this.pgpis = null;
				} else {
					pos += read;
					if (read < (len - pos)) {
						this.pgpis.close();
						this.pgpis = null;
					}
				}
			}
		}
		
		return pos == 0 ? -1 : pos;
	}
	
	private int readMore() throws IOException {
		// Read max lines so we can track the transfer encoding for especially attachments
		byte[] buffer = readLine();
		//TODO SEAN: I need to encode the attachment into base 64 but also need to replace the Content-Transfer-Encoding value and break the lines up appropriatly
		// This will not be easy as I either need to do this live in memory in an intelligent way or create a temp file and transfer contents there????
		//Base64.encode(data)
		if (buffer == null || buffer.length == 0) {
			this.buffer.flip();
			return -1;
		} else if (buffer.length >= ArmorInputStream.ARMOR_HEADER_PGP_MESSAGE.length && 
				Arrays.equals(ArmorInputStream.ARMOR_HEADER_PGP_MESSAGE, Arrays.copyOf(buffer, 
						ArmorInputStream.ARMOR_HEADER_PGP_MESSAGE.length))){
			// we have a PGP encrypted section so put the header back and start the decryption stream
			this.in.unread(buffer);
			this.pgpis = new PgpMessageInputStream(this.in);
			for (Iterator iterLoop = this.keyrings.iterator(); iterLoop.hasNext();) {
				Keyring keyring = (Keyring) iterLoop.next();
				this.pgpis.addKeyring(keyring);
			}
			for (Iterator iterLoop = this.secretKeys.iterator(); iterLoop.hasNext();) {
				Key key = (Key) iterLoop.next();
				this.pgpis.addSecretKey(key);
			}
			for (Iterator iterLoop = this.passwords.iterator(); iterLoop.hasNext();) {
				byte[] password = (byte[]) iterLoop.next();
				this.pgpis.addPassword(password);
			}
		} else if (buffer.length >= ArmorInputStream.ARMOR_FOOTER_PGP_MESSAGE.length && 
				Arrays.equals(ArmorInputStream.ARMOR_FOOTER_PGP_MESSAGE, Arrays.copyOf(buffer, 
						ArmorInputStream.ARMOR_FOOTER_PGP_MESSAGE.length))){
			// Let's ignore this and move on
			return readMore();
			
		} else {
			this.buffer.put(buffer);
		}
		this.buffer.flip();
		return this.buffer.remaining();
	}

	/**
	 * Reads a line of bytes and will return an empty array or null if th end of the stream is reached
	 * @return
	 * @throws IOException
	 */
	private byte[] readLine() throws IOException {
		int val = 0;
		int previousVal = 0;
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		while((val = in.read()) != -1) {
			bos.write(val);
			if (isLineFeed(val, previousVal)) {
				// We have a line so return all the bytes associated with this line
				return bos.toByteArray();
			}
			previousVal = val;
		}
		// We reached the end so we should return what we have
		return bos.toByteArray();
	}

	private static boolean isLineFeed(int val, int previousVal) {
		return (val == '\r' && previousVal == '\n') || val == '\n';
	}
	
	public void addKeyring(Keyring keyring)
	{
		keyrings.addElement(keyring);
	}
	
	public void addSecretKey(Key secretKey) throws UnrecoverableKeyException
	{
		// If the secret key has not been decrypted, this will
		// throw an exception.
		secretKey.getSecretKey();
		secretKeys.addElement(secretKey.getEncryptionKey());
		Logger.hexlog(
			this,
			Logger.DEBUG,
			"Added secret key: ",
			secretKey.getKeyID());
	}
	
	public void addPassword(byte[] password)
	{
		passwords.addElement(password);
	}
	

}
