// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Analyzer for C, C++, C#, and Java: https://pvs-studio.com

package demo.vulnerable;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IDORController {
  private final DocumentRepository repository;

  public IDORController(DocumentRepository repository) {
    this.repository = repository;
  }

  @GetMapping("/users/{userId}/docs")
  public Object getUserDocs(@PathVariable Long userId) {
    return repository.findByUserId(userId);
  }
}
