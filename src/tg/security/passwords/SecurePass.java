package tg.security.passwords;

import java.security.SecureRandom;
import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
	
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import java.util.Arrays;
import java.util.Base64;
import java.util.Random;

public class SecurePass {
	private static String _algorithm;  		// Algorithm identifier string Ex. "PBKDF2WithHmacSHA512"
	private static int _saltLength;    		// Desired salt length in bits
	private static int _derivedKeyLength;     	// Desired derived key length in bits
	private static int _iterations;    		// Iterations of the pbkdf2 algorithm	
	private static boolean _isInitialized = false; 	// Flag for whether SecurePass is initialized

	public SecurePass() {}
	
	public static synchronized void init(String algorithm,  
					     int keyLength, 
					     int saltLength, 
					     int iterations)
	{
		if (_isInitialized == false) {
			_algorithm = algorithm;
			_iterations = iterations;
			_saltLength = saltLength;
			_derivedKeyLength = keyLength + saltLength;
			_isInitialized = true;
		}
		else {
			throw new RuntimeException("Exception: Can only initialize once");
		}
	}
	
	private String[] formatHashReturnVal(byte[] salt, byte[] hash) {
		String[] record = {encodeBase64(salt), encodeBase64(hash)};
		
		return record;
	}
	
	private byte[] createSalt() {
		Random rand = new SecureRandom();
		byte[] salt = new byte[_saltLength];
		
		rand.nextBytes(salt);	
		
		return salt;
	}
	
	// For use with authenticate()
	private byte[] computeSaltedHash(char[] password, byte[] salt)  {
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
	
	public String[] computeSaltedHash(char[] password) {
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
		
		return formatHashReturnVal(salt, hash);
	}
	
	public boolean authenticate(char[] password, String storedSalt, String storedPw) {
		byte[] storedPw1  = decodeBase64(storedPw);
		byte[] storedSalt1 = decodeBase64(storedSalt);
		
		byte[] enteredPw = computeSaltedHash(password, storedSalt1);
			
		return slowEquals(enteredPw, storedPw1);		
	}	
	
	private boolean slowEquals(byte[] a, byte[] b) {	
		int isDifferent = a.length ^ b.length;
		
		for (int i = 0; i < a.length && i < b.length; ++i) {
			isDifferent |= a[i] ^ b[i];
		}
		
		return isDifferent == 0;	
	}
	
	public String encodeBase64(byte[] b) {	
		return Base64.getEncoder().encodeToString(b);
	}
	
	public byte[] decodeBase64(String str) {	
		return Base64.getDecoder().decode(str.getBytes(Charset.forName("UTF-8")));
	}
	
	public static String getAlgorithm() {
		return _algorithm;
	}
	
	public static int getSaltLength() {
		return _saltLength;
	}
	
	public static int getKeyLength() {
		return _derivedKeyLength;
	}
	
	public static int getIterations() {
		return _iterations;
	}	
}

