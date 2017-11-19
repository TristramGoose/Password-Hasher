package tg.security.passwords;

import java.security.SecureRandom;
import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
	
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import java.util.Base64;
import java.util.Random;

/**
 * <p>This class contains methods for the generation and comparison of hashes.</p>
 * 
 * <p> Algorithms available for use can be found in the
 * <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#SecretKeyFactory">
 * SecretKeyFactory section</a>	of the <br>Java Cryptography Architecture Standard Algorithm Name Documentation.</p>
 * 
 * <p>This class must be initialized before instantiation with the
 * {@link #init(String, int, int, int) init()} method.
 * <b>This can only be done once.</b></p> 
 * 
 * <p><b>The thread safety of this class is unknown</b></p>
 * 
 * @version 1.0
 * @author Tristan A. Guice
 */
public class SecurePass {
	/**Algorithm identifier String*/
	private static String _algorithm;
	
	/**Salt bit length*/
	private static int _saltLength;
	
	/** Derived key bit length*/
	private static int _derivedKeyLength;
	
	/** Number of times the algorithm should iterate*/
	private static int _iterations;
	
	/** Flag to check for SecurePass initialization */
	private static boolean _isInitialized = false; 	

	/** 
	 *  The Default Constructor
	 *  @throws SecurePassInitializationException if the class has yet to be initialized with
	 *  {@link #init(String, int, int, int) init()}
	 */
	public SecurePass() {
		if(_isInitialized == false) {
			throw new SecurePassInitializationException(
					"Exception: SecurePass must be initialized with init() first.");
		}
	}
	
	/**
	 * <p>Initializes the static member variables needed for hashing.</p>
	 * This method must be called before the class is instantiated.
	 * @param algorithm the algorithm identifier String. Click 
	 * 		  <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#SecretKeyFactory">Here</a>
	 * 		  for options.  
	 * @param hashLength the unsalted hash bit length
	 * @param saltLength the salt length in bits
	 * @param iterations the number of iterations used by the hashing algorithm
	 * @throws RuntimeException if the method is called more than once
	 */
	public static synchronized void init(String algorithm,  
					     int hashLength, 
					     int saltLength, 
					     int iterations)
	{
		if (_isInitialized == false) {
			_algorithm = algorithm;
			_iterations = iterations;
			_saltLength = saltLength;
			_derivedKeyLength = hashLength + saltLength;
			_isInitialized = true;
		}
		else {
			throw new RuntimeException("Exception: Can only initialize once");
		}
	}
	
	/**
	 * <p>Stores the hash and the salt used to salt the hash into an array
	 * and encodes them with base64 encoding.</p>
	 * <p>Index 0 contains the salt used
	 * to salt the hash and index 1 contains the salted hash.</p>
	 * @param salt the salt used to salt the hash
	 * @param hash the salted hash
	 * @return the salt used and the salted hash
	 */
	private String[] formatHashRec(byte[] salt, byte[] hash) {
		String[] record = {encodeBase64(salt), encodeBase64(hash)};
		
		return record;
	}
	
	/**
	 * Creates a cryptographically strong random number
	 * @return the salt
	 */
	private byte[] createSalt() {
		Random rand = new SecureRandom();
		byte[] salt = new byte[_saltLength];
		
		rand.nextBytes(salt);	
		
		return salt;
	}
	
	/**
	 * Computes a hash with a given salt
	 * 
	 * @param password the plain text password
	 * @param salt the salt used to salt the password
	 * @return the salted hash
	 * @throws IllegalArgumentException if the algorithm specified in  
	 * {@link #init(String, int, int, int) init()} doesn't exist or 
	 * if the key specification is invalid
	 */
	private byte[] computeHash(char[] password, byte[] salt)  {
		SecretKeyFactory sFactory;
		byte[] hash;
		
		PBEKeySpec spec = new PBEKeySpec(password, salt, _iterations, _derivedKeyLength);
	
		try {
			sFactory = SecretKeyFactory.getInstance(_algorithm);
			hash = sFactory.generateSecret(spec).getEncoded();
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalArgumentException(e);
		} catch (InvalidKeySpecException e) {
			throw new IllegalArgumentException(e);
		} finally {
			spec.clearPassword();
		}
		
		return hash;
	}
	
	/**
	 * Computes a hash from a char[], salts it, and key lengthens it
	 * @param password the plain text password
	 * @return the salt used in the hash (index 0) and the salted hash (index 1)
	 * @throws IllegalArgumentException if the algorithm specified in  
	 * {@link #init(String, int, int, int) init()} doesn't exist or 
	 * if the key specification is invalid
	 */
	public String[] computeHash(char[] password) {
		SecretKeyFactory sFactory;
		PBEKeySpec spec;
		byte[] hash = null;
		byte[] salt = createSalt();
		
		spec = new PBEKeySpec(password, salt, _iterations, _derivedKeyLength);
				
		try {
			sFactory = SecretKeyFactory.getInstance(_algorithm);
			hash = sFactory.generateSecret(spec).getEncoded();
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalArgumentException(e);
		} catch (InvalidKeySpecException e) {
			throw new IllegalArgumentException(e);
		} finally {
			spec.clearPassword();
		}
		
		return formatHashRec(salt, hash);
	}
	
	/**
	 * Compares a password with a hash to determine if the hash came from that password
	 * @param password the password to be hashed and compared
	 * @param salt the salt originally used to salt the hashed password
	 * @param hashedPw the salted and hashed password
	 * @return true if they matched
	 */
	public boolean authenticate(char[] password, String salt, String hashedPw) {
		byte[] hashedPw1  = decodeBase64(hashedPw);
		byte[] salt1 = decodeBase64(salt);
		
		byte[] pw = computeHash(password, salt1);
			
		return slowEquals(pw, hashedPw1);		
	}	
	
	/**
	 * Compares two byte[]s.
	 * <br>Method execution time is constant to prevent timing attacks
	 * @param a array to be compared
	 * @param b array to be compared
	 * @return true if the arrays are equal
	 */
	private boolean slowEquals(byte[] a, byte[] b) {	
		int isDifferent = a.length ^ b.length;
		
		for (int i = 0; i < a.length && i < b.length; ++i) {
			isDifferent |= a[i] ^ b[i];
		}
		
		return isDifferent == 0;	
	}
	
	/**
	 * Converts a byte[] into a String with base64 encoding
	 * @param b the byte array
	 * @return base64 encoded String
	 */
	private String encodeBase64(byte[] b) {	
		return Base64.getEncoder().encodeToString(b);
	}
	
	/**
	 * Converts and decodes a base64 encoded String into
	 * a byte[]
	 * @param str base64 encoded String
	 * @return decoded byte[] array
	 */
	private byte[] decodeBase64(String str) {	
		return Base64.getDecoder().decode(str.getBytes(Charset.forName("UTF-8")));
	}
	
	/**
	 * Returns the hashing algorithm in use.
	 * @return the hashing algorithm in use.
	 */
	public static String getAlgorithm() {
		return _algorithm;
	}
	
	/**
	 * Returns the salts set bit length.
	 * @return the salts set bit length. 
	 */
	public static int getSaltLength() {
		return _saltLength;
	}
	
	/**
	 * Returns the bit length of the key that {@link #computeHash(char[]) will return}
	 * @return the bit length of the key that {@link #computeHash(char[]) will return}
	 */
	public static int getKeyLength() {
		return _derivedKeyLength;
	}
	
	/** 
	 * Returns the number of iterations the hashing algorithm will perform
	 * @return the number of iterations the hashing algorithm will perform
	 */
	public static int getIterations() {
		return _iterations;
	}	
}

