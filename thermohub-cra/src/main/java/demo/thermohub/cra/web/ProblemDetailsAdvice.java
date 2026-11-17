package demo.thermohub.cra.web;

import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import demo.thermohub.cra.common.InvalidInputException;

/**
 * A10:2025 Mishandling of Exceptional Conditions – errors are RFC 9457 problem details.
 * <p>
 * Standard Spring MVC errors (malformed JSON, validation, type mismatch, 404) are handled by
 * {@link ResponseEntityExceptionHandler} with generic messages. Unexpected exceptions are logged
 * server-side with an incident reference; the client sees the reference, never the stack trace.
 */
@RestControllerAdvice
public class ProblemDetailsAdvice extends ResponseEntityExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(ProblemDetailsAdvice.class);

    @ExceptionHandler(InvalidInputException.class)
    public ResponseEntity<ProblemDetail> invalidInput(InvalidInputException e) {
        return problem(HttpStatus.BAD_REQUEST, e.getMessage());
    }

    @ExceptionHandler(RejectedRequestException.class)
    public ResponseEntity<ProblemDetail> rejected(RejectedRequestException e) {
        return problem(e.status(), e.getMessage());
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ProblemDetail> unexpected(Exception e) {
        String incident = UUID.randomUUID().toString();
        log.error("Unhandled exception, incident {}", incident, e);
        return problem(HttpStatus.INTERNAL_SERVER_ERROR, "Unexpected error. Incident reference: " + incident);
    }

    private static ResponseEntity<ProblemDetail> problem(HttpStatus status, String detail) {
        return ResponseEntity.status(status).body(ProblemDetail.forStatusAndDetail(status, detail));
    }
}
