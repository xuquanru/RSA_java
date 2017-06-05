package com.kamfu.yuyue.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;

import javax.crypto.Cipher;

import org.apache.tomcat.util.codec.binary.Base64;

import com.jfinal.kit.Prop;

public class RSAUtils {

	/**
	 * String to hold name of the encryption algorithm.
	 */
	public static final String ALGORITHM = "RSA";

	/**
	 * String to hold name of the encryption padding.
	 */
	public static final String PADDING = "RSA/NONE/NoPadding";

	/**
	 * String to hold name of the security provider.
	 */
	public static final String PROVIDER = "BC";

	/**
	 * String to hold the name of the private key file.
	 */
	public static final String PRIVATE_KEY_FILE = "D:/yuyue/work/private.key";

	/**
	 * String to hold name of the public key file.
	 */
	public static final String PUBLIC_KEY_FILE = "D:/yuyue/work/public.key";

	public static void generateKey() {
		try {

			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
			final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM, PROVIDER);
			keyGen.initialize(1024);
			final KeyPair key = keyGen.generateKeyPair();

			Prop prop=new Prop("jfinal.properties");
			String publicfile=	prop.get("publicfile");
			String privatefile=	prop.get("privatefile");
			File privateKeyFile = new File(privatefile);
			File publicKeyFile = new File(publicfile);

			// Create files to store public and private key
			if (privateKeyFile.getParentFile() != null) {
				privateKeyFile.getParentFile().mkdirs();
			}
			privateKeyFile.createNewFile();

			if (publicKeyFile.getParentFile() != null) {
				publicKeyFile.getParentFile().mkdirs();
			}
			publicKeyFile.createNewFile();

			// Saving the Public key in a file
			ObjectOutputStream publicKeyOS = new ObjectOutputStream(new FileOutputStream(publicKeyFile));
			publicKeyOS.writeObject(key.getPublic());
			publicKeyOS.close();

			// Saving the Private key in a file
			ObjectOutputStream privateKeyOS = new ObjectOutputStream(new FileOutputStream(privateKeyFile));
			privateKeyOS.writeObject(key.getPrivate());
			privateKeyOS.close();
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	public static boolean areKeysPresent() {
		Prop prop=new Prop("jfinal.properties");
		String publicfile=	prop.get("publicfile");
		String privatefile=	prop.get("privatefile");
		File privateKey = new File(privatefile);
		File publicKey = new File(publicfile);

		if (privateKey.exists() && publicKey.exists()) {
			return true;
		}
		return false;
	}

	public static byte[] encrypt(String text, PublicKey key) {
		byte[] cipherText = null;
		try {
			// get an RSA cipher object and print the provider
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
			final Cipher cipher = Cipher.getInstance(PADDING, PROVIDER);

			// encrypt the plain text using the public key
			cipher.init(Cipher.ENCRYPT_MODE, key);
			cipherText = cipher.doFinal(text.getBytes());
		} catch (Exception e) {
			e.printStackTrace();
		}
		return cipherText;
	}

	public static String decrypt(byte[] text, PrivateKey key) {
		byte[] dectyptedText = null;
		try {
			// get an RSA cipher object and print the provider
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
			final Cipher cipher = Cipher.getInstance(PADDING, PROVIDER);

			// decrypt the text using the private key
			cipher.init(Cipher.DECRYPT_MODE, key);
			dectyptedText = cipher.doFinal(text);

		} catch (Exception ex) {
			ex.printStackTrace();
		}

		return new String(dectyptedText);
	}


	public static String RSAEncode(String originalText) {
		String cipherTextBase64="";
		try {
			if (!areKeysPresent()) {
				generateKey();
			}

			ObjectInputStream inputStream = null;
			inputStream = new ObjectInputStream(new FileInputStream(PUBLIC_KEY_FILE));
			final PublicKey publicKey = (PublicKey) inputStream.readObject();
			final byte[] cipherText = encrypt(originalText, publicKey);
			Base64 base64 = new Base64();
			cipherTextBase64 = base64.encodeToString(cipherText);
			System.out.println("Original=" + originalText);
			System.out.println("Encrypted=" + cipherTextBase64);
			return cipherTextBase64;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return cipherTextBase64;

	}

	public static String RSADecode(String originalText) {
		String plainText="";
		try {
			ObjectInputStream inputStream = null;
			Base64 base64 = new Base64();
			byte[] cipherTextArray = base64.decode(originalText);
			inputStream = new ObjectInputStream(new FileInputStream(PRIVATE_KEY_FILE));
			final PrivateKey privateKey = (PrivateKey) inputStream.readObject();
			plainText = decrypt(cipherTextArray, privateKey);
			System.out.println("Decrypted=" + plainText);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return plainText;

	}

}
