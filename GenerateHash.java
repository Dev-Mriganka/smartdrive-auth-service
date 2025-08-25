import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class GenerateHash {
    public static void main(String[] args) {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        String clientSecret = "secret";
        String encodedSecret = encoder.encode(clientSecret);
        
        System.out.println("Original secret: " + clientSecret);
        System.out.println("Encoded secret: " + encodedSecret);
        
        // Verify it matches
        boolean matches = encoder.matches(clientSecret, encodedSecret);
        System.out.println("Matches: " + matches);
    }
}
