package tg.security.passwords;

/**
 * This exception is thrown by the {@link tg.security.passwords.SecurePass SecurePass}
 *  class when a constructor is called before the object has been initialized with the 
 * {@link tg.security.passwords.SecurePass#init(String, int, int, int)
 *  init(String, int, int, int)} method.
 * @author Tristan A. Guice
 *
 */
@SuppressWarnings("serial")
public class SecurePassInitializationException extends RuntimeException {
	public SecurePassInitializationException(String message) {
        super(message);
    }	
}
