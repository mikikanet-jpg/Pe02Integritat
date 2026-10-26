import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

/**
 * PE02 - Control d'integritat (SHA-256, fitxers i salt).
 */
public class Pe02Integritat {

    private static final String ALGORISME = "SHA-256";
    private static final int MIDA_SALT = 16; // bytes
    private static final Scanner sc = new Scanner(System.in);
    private static final SecureRandom random = new SecureRandom();

    /** Credencials d'un usuari: mai es guarda la contrasenya original. */
    private static class Credencials {
        final byte[] salt;
        final byte[] hash;
        Credencials(byte[] salt, byte[] hash) { this.salt = salt; this.hash = hash; }
    }

    private static final Map<String, Credencials> usuaris = new HashMap<>();

    // ------------------------------------------------------------------ utilitats

    private static byte[] sha256(byte[] dades) {
        try {
            return MessageDigest.getInstance(ALGORISME).digest(dades);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Algorisme no disponible: " + ALGORISME, e);
        }
    }

    private static byte[] sha256(String text) {
        return sha256(text.getBytes(StandardCharsets.UTF_8));
    }

    private static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b & 0xFF));
        return sb.toString();
    }

    private static byte[] generarSalt() {
        byte[] salt = new byte[MIDA_SALT];
        random.nextBytes(salt);
        return salt;
    }

    /** hash = SHA-256(salt || contrasenya) */
    private static byte[] hashAmbSalt(String contrasenya, byte[] salt) {
        byte[] pwd = contrasenya.getBytes(StandardCharsets.UTF_8);
        byte[] entrada = new byte[salt.length + pwd.length];
        System.arraycopy(salt, 0, entrada, 0, salt.length);
        System.arraycopy(pwd, 0, entrada, salt.length, pwd.length);
        return sha256(entrada);
    }

    private static String llegir(String missatge) {
        System.out.print(missatge);
        return sc.nextLine();
    }

    //Part 1

    private static void part1() {
        System.out.println("\n--- PART 1: Calcul de resums (SHA-256) ---");
        System.out.println("1. Hash d'un missatge");
        System.out.println("2. Comparar dos missatges");
        System.out.println("3. Calcular, modificar i tornar a calcular");
        System.out.println("4. Repetir el calcul diverses vegades");
        switch (llegir("Opcio: ").trim()) {
            case "1": {
                String m = llegir("Missatge: ");
                System.out.println("Hash: " + hex(sha256(m)));
                break;
            }
            case "2": {
                String a = llegir("Missatge 1: ");
                String b = llegir("Missatge 2: ");
                String ha = hex(sha256(a)), hb = hex(sha256(b));
                System.out.println("Hash 1: " + ha);
                System.out.println("Hash 2: " + hb);
                System.out.println(ha.equals(hb) ? "Els hashes COINCIDEIXEN." : "Els hashes son DIFERENTS.");
                break;
            }
            case "3": {
                String m = llegir("Missatge original: ");
                System.out.println("Hash original: " + hex(sha256(m)));
                String m2 = llegir("Missatge modificat: ");
                System.out.println("Hash modificat: " + hex(sha256(m2)));
                break;
            }
            case "4": {
                String m = llegir("Missatge: ");
                String primer = hex(sha256(m));
                boolean igual = true;
                for (int i = 1; i <= 5; i++) {
                    String h = hex(sha256(m));
                    System.out.println("Calcul " + i + ": " + h);
                    igual &= h.equals(primer);
                }
                System.out.println(igual ? "El resultat es manté sempre igual (determinista)."
                                         : "El resultat ha canviat!");
                break;
            }
            default:
                System.out.println("Opcio no valida.");
        }
    }

    //Part 2

    private static void part2() {
        System.out.println("\n--- PART 2: Verificacio de la integritat ---");
        Path fMissatge = Paths.get("missatge.txt");
        Path fHash = Paths.get("missatge.hash");
        Path fCanviat = Paths.get("missatgeCanviat.txt");
        try {
            // Emissor
            String contingut = llegir("[Emissor] Contingut del missatge: ");
            Files.write(fMissatge, contingut.getBytes(StandardCharsets.UTF_8));
            String hashOriginal = hex(sha256(Files.readAllBytes(fMissatge)));
            Files.write(fHash, hashOriginal.getBytes(StandardCharsets.UTF_8));
            // Versio modificada per poder fer la prova
            Files.write(fCanviat, (contingut + " (modificat)").getBytes(StandardCharsets.UTF_8));
            System.out.println("Desat missatge.txt, missatge.hash i missatgeCanviat.txt (versio modificada).");
            System.out.println("Hash original: " + hashOriginal);

            // Receptor
            System.out.println("\n[Receptor] Simulant la recepcio del missatge...");
            String nom = llegir("Nom del fitxer rebut (missatge.txt / missatgeCanviat.txt): ").trim();
            Path rebut = Paths.get(nom);
            if (!Files.exists(rebut)) {
                System.out.println("El fitxer no existeix.");
                return;
            }
            String hashRebut = hex(sha256(Files.readAllBytes(rebut)));
            String hashGuardat = new String(Files.readAllBytes(fHash), StandardCharsets.UTF_8).trim();
            System.out.println("Hash original: " + hashGuardat);
            System.out.println("Hash rebut:    " + hashRebut);
            System.out.println(hashGuardat.equals(hashRebut)
                    ? "OK: els hashes coincideixen, el missatge no s'ha modificat."
                    : "ALERTA: els hashes no coincideixen, s'ha detectat una modificacio!");
        } catch (IOException e) {
            System.out.println("Error d'E/S: " + e.getMessage());
        }
    }

    // Part 3

    private static boolean registrar(String nom, String contrasenya) {
        if (usuaris.containsKey(nom)) return false;
        byte[] salt = generarSalt();
        usuaris.put(nom, new Credencials(salt, hashAmbSalt(contrasenya, salt)));
        return true;
    }

    private static void part3() {
        System.out.println("\n--- PART 3: Registre d'usuaris amb salt ---");
        String nom = llegir("Nom d'usuari: ").trim();
        String pwd = llegir("Contrasenya: ");
        if (nom.isEmpty() || pwd.isEmpty()) {
            System.out.println("Cal indicar usuari i contrasenya.");
            return;
        }
        if (!registrar(nom, pwd)) {
            System.out.println("Aquest usuari ja existeix.");
            return;
        }
        pwd = null; // no es conserva la contrasenya original
        Credencials c = usuaris.get(nom);
        System.out.println("Usuari registrat.");
        System.out.println("  Salt: " + hex(c.salt));
        System.out.println("  Hash: " + hex(c.hash));
    }

    // ------------------------------------------------------------------ Part 4

    private static boolean autenticar(String nom, String contrasenya) {
        Credencials c = usuaris.get(nom);
        if (c == null) return false;
        byte[] calculat = hashAmbSalt(contrasenya, c.salt);
        return MessageDigest.isEqual(calculat, c.hash); // comparacio en temps constant
    }

    private static void part4() {
        System.out.println("\n--- PART 4: Inici de sessio ---");
        String nom = llegir("Nom d'usuari: ").trim();
        String pwd = llegir("Contrasenya: ");
        if (!usuaris.containsKey(nom)) {
            System.out.println("Error: l'usuari no esta registrat.");
        } else if (autenticar(nom, pwd)) {
            System.out.println("Acces permes. Benvingut, " + nom + "!");
        } else {
            System.out.println("Error: contrasenya incorrecta.");
        }
    }

    // ------------------------------------------------------------------ main

    public static void main(String[] args) {
        boolean sortir = false;
        while (!sortir) {
            System.out.println("\n===== PE02 - Control d'integritat =====");
            System.out.println("1. Calcul de resums");
            System.out.println("2. Verificacio de la integritat de missatges");
            System.out.println("3. Registrar usuari");
            System.out.println("4. Iniciar sessio");
            System.out.println("0. Sortir");
            switch (llegir("Opcio: ").trim()) {
                case "1": part1(); break;
                case "2": part2(); break;
                case "3": part3(); break;
                case "4": part4(); break;
                case "0": sortir = true; break;
                default: System.out.println("Opcio no valida.");
            }
        }
        sc.close();
    }
}