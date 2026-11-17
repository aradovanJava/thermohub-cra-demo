package demo.thermohub.cra.web;

import org.springframework.http.HttpStatus;

/** A request refused on purpose, with a status and a message that is safe to show to the caller. */
public class RejectedRequestException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final HttpStatus status;

    public RejectedRequestException(HttpStatus status, String safeMessage) {
        super(safeMessage);
        this.status = status;
    }

    public HttpStatus status() {
        return status;
    }
}
