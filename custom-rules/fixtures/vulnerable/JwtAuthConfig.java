package demo.vulnerable;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;

public class JwtAuthConfig {
  public Object weakParser(String token) {
    return Jwts.parser()
      .setSigningKey("short-secret")
      .parseClaimsJws(token)
      .getBody();
  }

  public Object weakKeyFactory(String token) {
    return Jwts.parserBuilder()
      .setSigningKey(Keys.hmacShaKeyFor("tiny-secret".getBytes(StandardCharsets.UTF_8)))
      .build()
      .parseClaimsJws(token)
      .getBody();
  }
}
