import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.ArrayList;
import java.util.List;

public class Storage {
    private static final Path VAULT_FILE = Path.of("PVault.txt");
    private final SecretKeySpec aesKey;

    // Constructor: derive AES key from master PIN
    public Storage(int pin) {
        byte[] salt = loadOrGenerateSalt();
        this.aesKey = deriveKey(pin, salt);
    }

    // Save a vault entry (label, username, password)
    public void saveEntry(String label, String username, String password) {
        try {
            String raw = label + ":" + username + "|" + password;
            String encrypted = encrypt(raw, aesKey);
            Files.writeString(VAULT_FILE, encrypted + System.lineSeparator(),
                    Files.exists(VAULT_FILE) ? java.nio.file.StandardOpenOption.APPEND : java.nio.file.StandardOpenOption.CREATE);
        } catch (Exception e) {
            throw new RuntimeException("Failed to save entry", e);
        }
    }

    public void deleteEntry(String labelToDelete) {
        try {
            // Read all lines from the vault file
            List<String> encryptedLines = Files.readAllLines(VAULT_FILE);
            List<String> updatedEncryptedLines = new ArrayList<>();

            for (String encrypted : encryptedLines) {
                String decrypted = decrypt(encrypted, aesKey);
                String[] parts = decrypted.split(":", 2); // label:username|password
                if (parts.length == 2) {
                    String label = parts[0];
                    if (!label.equals(labelToDelete)) {
                        updatedEncryptedLines.add(encrypted); // keep non-matching entries
                    }
                }
            }
            // Overwrite the file with updated entries
            Files.write(VAULT_FILE, updatedEncryptedLines, java.nio.file.StandardOpenOption.TRUNCATE_EXISTING);
        } catch (Exception e) {
            throw new RuntimeException("Failed to delete entry", e);
        }
    }

    // Load and decrypt all entries
    public List<String> loadEntries() {
        try {
            if (!Files.exists(VAULT_FILE)) return new ArrayList<>();
            List<String> lines = Files.readAllLines(VAULT_FILE);
            List<String> decrypted = new ArrayList<>();
            for (String line : lines) {
                decrypted.add(decrypt(line, aesKey));
            }
            return decrypted;
        } catch (Exception e) {
            throw new RuntimeException("Failed to load entries", e);
        }
    }

    // AES encryption
    private String encrypt(String data, SecretKeySpec key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] encrypted = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(iv) + ":" + Base64.getEncoder().encodeToString(encrypted);
    }

    // AES decryption
    private String decrypt(String encryptedData, SecretKeySpec key) throws Exception {
        String[] parts = encryptedData.split(":");
        byte[] iv = Base64.getDecoder().decode(parts[0]);
        byte[] encrypted = Base64.getDecoder().decode(parts[1]);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] decrypted = cipher.doFinal(encrypted);
        return new String(decrypted);
    }

    // Derive AES key from PIN and salt
    private SecretKeySpec deriveKey(int pin, byte[] salt) {
        try {
            KeySpec spec = new PBEKeySpec(String.valueOf(pin).toCharArray(), salt, 65536, 128);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] key = factory.generateSecret(spec).getEncoded();
            return new SecretKeySpec(key, "AES");
        } catch (Exception e) {
            throw new RuntimeException("Failed to derive key", e);
        }
    }

    // Load salt from file or generate new
    private byte[] loadOrGenerateSalt() {
        Path saltFile = Path.of("vault.salt");
        try {
            if (Files.exists(saltFile)) {
                return Base64.getDecoder().decode(Files.readString(saltFile));
            } else {
                byte[] salt = new byte[16];
                new SecureRandom().nextBytes(salt);
                Files.writeString(saltFile, Base64.getEncoder().encodeToString(salt));
                return salt;
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to load or generate salt", e);
        }
    }
}

