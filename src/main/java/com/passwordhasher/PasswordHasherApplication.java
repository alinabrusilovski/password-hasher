package com.passwordhasher;

import java.util.Random;
import java.util.Scanner;

public class PasswordHasherApplication {

    public static void main(String[] args) throws Exception {
        PasswordHasher hasher = new PasswordHasher(new Random());

        Scanner scanner = new Scanner(System.in);

        while (true) {
            System.out.println("Enter your password: ");
            String password = scanner.nextLine();

            String hashedPassword = hasher.generateHash(password);

            System.out.println("Your hashed password is: " + hashedPassword);

            System.out.println("Do you want to hash another password? (y/n)");

            String response = scanner.nextLine();
            if (response.equalsIgnoreCase("n")) {
                break;
            }
        }

    }
}
