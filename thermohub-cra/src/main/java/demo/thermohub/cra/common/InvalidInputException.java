package demo.thermohub.cra.common;

/**
 * Input that violates a domain rule. Mapped to HTTP 400 with a generic, non-reflective message.
 * Deliberately free of framework types so domain primitives stay plain Java.
 */
public class InvalidInputException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public InvalidInputException(String message) {
        super(message);
    }
}
