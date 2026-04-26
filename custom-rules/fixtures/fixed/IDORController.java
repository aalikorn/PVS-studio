package demo.fixed;

import java.security.Principal;
import java.util.Objects;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IDORController {
  private final DocumentRepository repository;

  public IDORController(DocumentRepository repository) {
    this.repository = repository;
  }

  @GetMapping("/users/{userId}/docs")
  public Object getUserDocs(@PathVariable Long userId, Principal principal) {
    Long authenticatedUserId = Long.valueOf(principal.getName());
    boolean isAdmin = false;

    if (!Objects.equals(authenticatedUserId, userId) && !isAdmin) {
      throw new ForbiddenException();
    }

    return repository.findByUserId(userId);
  }

  @ResponseStatus(HttpStatus.FORBIDDEN)
  private static class ForbiddenException extends RuntimeException {
  }
}
