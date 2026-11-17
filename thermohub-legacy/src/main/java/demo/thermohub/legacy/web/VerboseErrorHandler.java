package demo.thermohub.legacy.web;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.web.ErrorResponse;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * A10:2025 Mishandling of Exceptional Conditions (and A02) – every error returns the exception and
 * the full stack trace "so support can debug customer issues". Attackers read it too: class names,
 * library versions, SQL fragments.
 */
@RestControllerAdvice
public class VerboseErrorHandler {

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handle(Exception e) {
        int status = (e instanceof ErrorResponse errorResponse) ? errorResponse.getStatusCode().value() : 500;
        StringWriter trace = new StringWriter();
        e.printStackTrace(new PrintWriter(trace));
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", status);
        body.put("error", e.toString());
        body.put("trace", trace.toString());
        return ResponseEntity.status(status).body(body);
    }
}
