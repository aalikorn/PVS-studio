// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Analyzer for C, C++, C#, and Java: https://pvs-studio.com

package demo.fixed;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;

public class JwtAuthConfig {
  private static final String SECRET = "01234567890123456789012345678901";

  public Object strongParser(String token) {
    return Jwts.parserBuilder()
      .requireIssuer("idor-jwt-demo")
      .requireAudience("web")
      .setSigningKey(Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8)))
      .build()
      .parseClaimsJws(token)
      .getBody();
  }
}
