import tg.security.passwords.SecurePass;

/*
 * Test class: Contains some of the basic tests that have been run so far.
 */

public class Test {
	public static void main(String[] args) {
		/*
		 * See available algorithm options under the SecretKeyFactory section of this link
		 * https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#SecretKeyFactory
		 */
			
		final String ALGORITHM = "PBKDF2WithHmacSHA512";
		final String ALGORITHM1 = "PBKDF2WithHmacSHA256";
		final String ALGORITHM2 = "PBKDF2WithHmacSHA1";
		final int ITERATIONS = 50000;
		final int SALT_LENGTH = 64; 					  // Bits
		final int DESIRED_KEY_LENGTH = 512 + SALT_LENGTH; // Bits
		
		// Initializes SecurePass, can only be called once. SHOULD be thread safe
		SecurePass.init(ALGORITHM, DESIRED_KEY_LENGTH, SALT_LENGTH, ITERATIONS);
		
		SecurePass pass = new SecurePass();
		String pw = "Test_Password";
		char[] testPw = pw.toCharArray();
		
		// Record[0] has the salt used. Record[1] has the hash
		String[] record = pass.computeHash(testPw);
		
		String sMessage = "authentication: SUCCESS!\n";
		String fMessage = "authentication: FAILED\n";
		testPasswordAuthentication(pass, record,  testPw, sMessage, fMessage);
	}

	
	/* 
	 * Tests whether two passwords match when hashed with the same salt
	 */
	private static void testPasswordAuthentication(SecurePass pass,
												   String[] record, 
												   char[] testPw, 
						                           String sMessage, 
						                           String fMessage) 
	{	 
		if(pass.authenticate(testPw, record[0], record[1])) {
			System.out.println(sMessage);
		}
		else
		{
			System.out.println(fMessage);
		}
	}
}