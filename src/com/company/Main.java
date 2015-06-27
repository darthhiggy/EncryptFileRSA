package com.company;

import java.security.*;
import java.security.spec.*;

import javax.crypto.*;
import javax.crypto.spec.*;

import java.io.*;
import java.util.*;

public class Main
{
    //Number of times the password will be hashed with MD5 when transforming it into a TripleDES key.
    private static final int ITERATIONS = 1000;
    private static final String ENCRYPTED_FILENAME_SUFFIX = ".encrypted";
    private static final String DECRYPTED_FILENAME_SUFFIX = ".decrypted";
    /**
     * FileEncryptor is started with one of three options:
     *
     * -c: create key pair and write it to 2 files
     * -e: encrypt a file, given as an argument
     * -d: decrypt a file, given as an argument
     */
    public static void main(String[] args) throws Exception
    {
        int choice = 1;
        while(choice!=0)
        {
            System.out.print("1: for create key \n2: for encrypt \n3: for decrypt \n0: to exit \nChoose: ");
            Scanner scan1 = new Scanner(System.in);
            choice = scan1.nextInt();
            scan1.nextLine();
            if(choice==1)
            {
                createKey();
            }
            else if(choice==2)
            {
                System.out.println("Name of file to encrypt: ");
                String inputFile = scan1.nextLine();
                encrypt(inputFile);
            }
            else if(choice==3)
            {
                System.out.println("Enter name of Encrypted file: ");
                String inputFile = scan1.nextLine();
                decrypt(inputFile);
            }
            else if(choice==0)
            {
                System.out.println("Exiting application ....");
                System.out.println("Good-bye");
            }
            else
            {
                System.out.println("Improper response");
            }
        }
    }

    /**
     * Creates a 1024 bit RSA key and stores it as 2 files, one for the private, one for the public half of the key.
     * The public key is safe to expose to anyone, so we will write it directly to the filesystem unencrypted.
     * You should set file permissions, though, so that that no one can modify it.
     * @throws Exception
     */
    private static void createKey() throws Exception
    {
        Scanner scan = new Scanner(System.in);
        String publicKeyFilename, privateKeyFilename;

        // Prompt the user to enter password to encrypt the private key
        System.out.println("Password to encrypt the private key: ");
        char[] password = scan.nextLine().toCharArray();

        // Prompt the user for a filename to use to store the public key
        System.out.println("Public key filename: ");
        publicKeyFilename = scan.nextLine();

        // Prompt the user for a filename to use to store the private key
        System.out.println("Private key filename: ");
        privateKeyFilename = scan.nextLine();

        // Create an RSA key pair - 1024 bytes
        SecureRandom random = new SecureRandom();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
        generator.initialize(1024, random);	 // generator.initialize(key size, source of randomness)
        KeyPair pair = generator.generateKeyPair();
        Key pubKey = pair.getPublic();
        Key privKey = pair.getPrivate();
        System.out.println("Done generating the keypair.\n");

        // Print out public key bytes
        System.out.println("Public key bytes: " + CryptoUtils.toHex(pubKey.getEncoded()));

        // Print out private key bytes
        System.out.println("Private key bytes: " + CryptoUtils.toHex(privKey.getEncoded()));

        // Call passwordEncrypt to encrypt private key
        byte[] encPrivKey = passwordEncrypt(password, privKey.getEncoded());

        // Write it out
        FileOutputStream pubFos = new FileOutputStream(publicKeyFilename);
        pubFos.write(pubKey.getEncoded());

        FileOutputStream privFos = new FileOutputStream(privateKeyFilename);
        privFos.write(encPrivKey);

        // Close file output streams
        pubFos.close();
        privFos.close();
    }

    /**
     * Reads bytes from a file into a byte array
     * @param textFile a filename stored in a String
     * @return a byte array containing the file contents
     * @throws IOException
     */
    private static byte[] readFromFile(String textFile) throws IOException
    {
        FileInputStream fis = new FileInputStream(textFile);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        int i = 0;

        while((i = fis.read())!= -1)
            baos.write(i);

        fis.close();

        byte[] message = baos.toByteArray();

        baos.close();
        fis.close();

        return message;
    }

    /**
     * @param fileName a String containing the filename containing the public key
     * @return the unencrypted public key
     * @throws Exception
     */
    public static PublicKey loadPublicKey(String fileName) throws Exception
    {
        // Load the public key bytes
        byte[] keyBytes = readFromFile(fileName);

        // Turn the encoded key into a real RSA public key. Public keys are encoded in X.509
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory myFactory = KeyFactory.getInstance("RSA");
        PublicKey pubKey = myFactory.generatePublic(keySpec);

        // Print out key
        //System.out.println("Loaded public key: " + CryptoUtils.toHex(pubKey.getEncoded()));

        // Return public key
        return pubKey;
    }

    /**
     * @param fileName
     * @param password
     * @return the private key
     * @throws Exception
     */
    public static PrivateKey loadPrivateKey(String fileName, char[] password) throws Exception
    {
        byte[] allBytes = readFromFile(fileName);
        byte[] decryptedPrivateKeyBytes = passwordDecrypt(password, allBytes);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decryptedPrivateKeyBytes);
        KeyFactory myFactory = KeyFactory. getInstance("RSA");
        PrivateKey privKey = myFactory.generatePrivate(keySpec);
        //System.out.println("private key bytes: " + CryptoUtils.toHex(privKey.getEncoded()));
        return privKey;
    }

    /**
     * This method will create a different symmetric key for each file that we encrypt.
     * We will then store the key, encrypted with RSA, in the encrypted file.
     * The format of the file: length of key, encrypted key, IV (16 bytes), and ciphertext.
     *
     * @param fileInput
     * @throws Exception
     */
    private static void encrypt(String fileInput) throws Exception
    {
        //ask user for file name to store public key
        Scanner scan = new Scanner(System.in);
        System.out.print("\nEnter public key filename to load from: ");
        String filename = scan.nextLine();

        PublicKey pub = loadPublicKey(filename);

        String fileOut = fileInput + ENCRYPTED_FILENAME_SUFFIX;
        // let an application write primitive java data type to an output stream
        DataOutputStream output = new DataOutputStream(new FileOutputStream(fileOut));
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, pub);
        KeyGenerator generator = KeyGenerator.getInstance("AES", "BC");
        generator.init(256, new SecureRandom());
        Key encryptionKey = generator.generateKey();
        byte[]encKey = rsaCipher.doFinal(encryptionKey.getEncoded());
        output.writeInt(encKey.length);
        output.write(encKey);
        byte[] ivBytes = new byte[16];
        SecureRandom rand = new SecureRandom();
        rand.nextBytes(ivBytes);
        output.write(ivBytes);
        IvParameterSpec spec = new IvParameterSpec(ivBytes);
        Cipher Enc = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
        Enc.init(Cipher.ENCRYPT_MODE, encryptionKey, spec);
        FileInputStream fis = new FileInputStream(fileInput);
        CipherOutputStream cos = new CipherOutputStream(output, Enc);
        System.out.println("Encrypting the file ...");
        int theByte = 0;
        while((theByte = fis.read()) != -1)
        {
            //System.out.print(theByte + " ");
            cos.write(theByte);
        }
        fis.close();
        cos.close();
    }

    /**
     * Decrypts the given file by getting the RSA private key and decrypting the session key
     * embedded in the file. Then decrypts the file with that session key.
     *
     * @param fileInput
     * @throws Exception
     */
    private static void decrypt(String fileInput) throws Exception
    {
        Scanner dScan = new Scanner(System.in);
        System.out.println("Enter file name and path for private key: ");
        String privKeyFile = dScan.nextLine();

        System.out.println("Enter the password: ");
        String password = dScan.nextLine();

        char[] pass = password.toCharArray();
        PrivateKey privKey = loadPrivateKey(privKeyFile, pass);

        DataInputStream dis = new DataInputStream(new FileInputStream(fileInput));
        byte[] encryptedKeyBytes = new byte[dis.readInt()];
        dis.readFully(encryptedKeyBytes);
        // initialize rasCipher
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.DECRYPT_MODE, privKey);
        //decrypt those bytes
        byte[] decryptedKeyBytes = rsaCipher.doFinal(encryptedKeyBytes);
        //use the secretKeySpec class, we can transform the decrypted session key into a secret spec
        SecretKey aesKey = new SecretKeySpec(decryptedKeyBytes, "AES");
        //to decrypt the contents of the file, we need our oringal IV, which is next 16 bytes
        byte[] iv = new byte[16];
        dis.read(iv);
        IvParameterSpec spec = new IvParameterSpec(iv);
        Cipher Dec = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
        Dec.init(Cipher.DECRYPT_MODE, aesKey, spec);
        CipherInputStream cis = new CipherInputStream(dis, Dec);
        System.out.println("Decrypting the file....");
        FileOutputStream fos = new FileOutputStream(fileInput+DECRYPTED_FILENAME_SUFFIX);
        int theByte = 0;
        while((theByte = cis.read()) != -1)
        {
            //System.out.print(theByte + " ");
            fos.write(theByte);
        }
        fos.close();
        cis.close();
    }

    /**
     * Given a password and some plaintext, it will return the appropriate ciphertext.
     * A salt is used, and will be the first 8 bytes of the array returned.
     *
     * @param password
     * @param plaintext
     * @return a byte array containing the salt and encrypted private key
     * @throws Exception
     */
    private static byte[] passwordEncrypt(char[] password, byte[] plaintext) throws Exception
    {
        // Create 8 byte random salt
        byte[] salt = new byte[8];
        SecureRandom random = new SecureRandom();
        random.nextBytes(salt);

        // Create key based on password
        PBEKeySpec pbeSpec = new PBEKeySpec(password, salt, ITERATIONS);
        SecretKeyFactory keyFact = SecretKeyFactory.getInstance("PBEWithSHAAnd3KeyTripleDES");
        Key key = keyFact.generateSecret(pbeSpec);

        // Create a cipher and initialize it for encrypting
        Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS7Padding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        // Encrypt plaintext
        byte[] cipherText = cipher.doFinal(plaintext);

        // Write out salt and ciphertext
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(salt);
        baos.write(cipherText);

        return baos.toByteArray();
    }

    /**
     * Utility method to decrypt a byte array with a given password.
     * Salt will be the first 8 bytes in the array passed in.
     *
     * @param password a char array containing the password
     * @param ciphertext a byte array containing ciphertext
     * @return a byte array containing decrypted text
     * @throws Exception
     */
    private static byte[] passwordDecrypt(char[] password, byte[] ciphertext) throws Exception
    {
        // Read in the salt - the remaining bytes are the actual ciphertext
        byte[] salt = new byte[8];
        System.arraycopy(ciphertext, 0, salt, 0, 8);

        // Get the encrypted key bytes
        byte[] keybytes = new byte[ciphertext.length - salt.length];
        System.arraycopy(ciphertext, 8, keybytes, 0, ciphertext.length-8);

        // Create the PBE cipher
        PBEKeySpec pbeSpec = new PBEKeySpec(password, salt, ITERATIONS);
        SecretKeyFactory keyFact = SecretKeyFactory.getInstance("PBEWithSHAAnd3KeyTripleDES");
        Key key = keyFact.generateSecret(pbeSpec);

        Cipher cipher = Cipher.getInstance("PBEWithSHAAnd3KeyTripleDES", "BC");
        cipher.init(Cipher.DECRYPT_MODE, key);

        // Decrypt the key bytes
        byte[] plaintext = cipher.doFinal(keybytes);

        // Return plaintext
        return plaintext;
    }

}
