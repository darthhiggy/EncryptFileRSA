package com.company;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class CryptoUtils {

	/**
	 * Convert a byte array of 8 bit characters into a String.
	 * 
	 * @param bytes
	 *            the array containing the characters
	 * @param length
	 *            the number of bytes to process
	 * @return a String representation of bytes
	 */
	public static String toString(byte[] bytes, int length) {
		char[] chars = new char[length];

		for (int i = 0; i != chars.length; i++) {
			chars[i] = (char) (bytes[i] & 0xff);
		}

		return new String(chars);
	}

	/**
	 * Convert a byte array of 8 bit characters into a String.
	 * 
	 * @param bytes
	 *            the array containing the characters
	 * @return a String representation of bytes
	 */
	public static String toString(byte[] bytes) {
		return toString(bytes, bytes.length);
	}

	/**
	 * Convert the passed in String to a byte array by taking the bottom 8 bits
	 * of each character it contains.
	 * 
	 * @param string
	 *            the string to be converted
	 * @return a byte array representation
	 */
	public static byte[] toByteArray(String string) {
		byte[] bytes = new byte[string.length()];
		char[] chars = string.toCharArray();

		for (int i = 0; i != chars.length; i++) {
			bytes[i] = (byte) chars[i];
		}

		return bytes;
	}

	private static String digits = "0123456789abcdef";

	/**
	 * Return length many bytes of the passed in byte array as a hex string.
	 * 
	 * @param data
	 *            the bytes to be converted.
	 * @param length
	 *            the number of bytes in the data block to be converted.
	 * @return a hex representation of length bytes of data.
	 */
	public static String toHex(byte[] data, int length) {
		StringBuffer buf = new StringBuffer();

		for (int i = 0; i != length; i++) {
			int v = data[i] & 0xff;

			buf.append(digits.charAt(v >> 4));
			buf.append(digits.charAt(v & 0xf));
		}

		return buf.toString();
	}

	/**
	 * Return the passed in byte array as a hex string.
	 * 
	 * @param data
	 *            the bytes to be converted.
	 * @return a hex representation of data.
	 */
	public static String toHex(byte[] data) {
		return toHex(data, data.length);
	}

	/**
	 * Create a key for use with AES.
	 * 
	 * @param bitLength
	 * @param random
	 * @return an AES key.
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 */
	public static SecretKey createAESKey(int bitLength, SecureRandom random)
			throws NoSuchAlgorithmException, NoSuchProviderException {
		KeyGenerator generator = KeyGenerator.getInstance("AES", "BC");

		generator.init(256, random);

		return generator.generateKey();
	}

	/**
	 * Create an IV suitable for using with AES in CTR mode.
	 * <p>
	 * The IV will be composed of 4 bytes of message number, 4 bytes of random
	 * data, and a counter of 8 bytes.
	 * 
	 * @param messageNumber
	 *            the number of the message.
	 * @param random
	 *            a source of randomness
	 * @return an initialised IvParameterSpec
	 */
	public static IvParameterSpec createAESCtrIv(SecureRandom random) {
		byte[] ivBytes = new byte[16];

		// initially randomize

		random.nextBytes(ivBytes);

		return new IvParameterSpec(ivBytes);
	}

}
