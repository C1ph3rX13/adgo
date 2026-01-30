package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/term"
)

// setup runs the interactive configuration wizard
func setup() {
	fmt.Println("No configuration file found and missing required flags.")
	fmt.Println("Starting interactive setup wizard...")
	fmt.Println()

	scanner := bufio.NewScanner(os.Stdin)

	// Server
	cfg.LDAP.Server = prompt(scanner, "Domain Controller Host/IP: ", func(input string) error {
		if strings.TrimSpace(input) == "" {
			return fmt.Errorf("server address cannot be empty")
		}
		return nil
	}, false)

	// Port
	portStr := prompt(scanner, "LDAP Port [389]: ", func(input string) error {
		if input == "" {
			return nil
		}
		p, err := strconv.Atoi(input)
		if err != nil || p < 1 || p > 65535 {
			return fmt.Errorf("invalid port: must be between 1-65535")
		}
		return nil
	}, false)
	if portStr == "" {
		cfg.LDAP.Port = 389
	} else {
		cfg.LDAP.Port, _ = strconv.Atoi(portStr)
	}

	// BaseDN
	cfg.LDAP.BaseDN = prompt(scanner, "Base DN (e.g., DC=sec,DC=lab): ", func(input string) error {
		if strings.TrimSpace(input) == "" {
			return fmt.Errorf("base DN cannot be empty")
		}
		if !strings.Contains(strings.ToUpper(input), "DC=") {
			return fmt.Errorf("base DN usually contains 'DC=' components")
		}
		return nil
	}, false)

	// Username
	cfg.LDAP.Username = prompt(scanner, "Username: ", func(input string) error {
		if strings.TrimSpace(input) == "" {
			return fmt.Errorf("username cannot be empty")
		}
		return nil
	}, false)

	// Password
	cfg.LDAP.Password = prompt(scanner, "Password: ", nil, true)

	// Save option
	save := prompt(scanner, "Save this configuration for future use? [Y/n]: ", nil, false)
	if save == "" || strings.ToLower(save) == "y" || strings.ToLower(save) == "yes" {
		if err := Save(); err != nil {
			fmt.Printf("Error saving configuration: %v\n", err)
		} else {
			fmt.Printf("Configuration saved to %s\n", GetDefaultConfigPath())
		}
	}

	// Sync to viper for consistency
	viperApp.Set("ldap.server", cfg.LDAP.Server)
	viperApp.Set("ldap.port", cfg.LDAP.Port)
	viperApp.Set("ldap.baseDN", cfg.LDAP.BaseDN)
	viperApp.Set("ldap.username", cfg.LDAP.Username)
	viperApp.Set("ldap.password", cfg.LDAP.Password)

	fmt.Println("\nSetup complete. Running command...")
	fmt.Println()
}

// prompt helper for user input
func prompt(scanner *bufio.Scanner, label string, validator func(string) error, isPassword bool) string {
	if isPassword {
		fmt.Print(label)
		bytePassword, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			return ""
		}
		password := string(bytePassword)
		if validator != nil {
			if err := validator(password); err != nil {
				fmt.Printf("Error: %v\n", err)
				return prompt(scanner, label, validator, isPassword)
			}
		}
		return password
	}

	for {
		fmt.Print(label)
		if !scanner.Scan() {
			return ""
		}
		input := strings.TrimSpace(scanner.Text())

		if validator != nil {
			if err := validator(input); err != nil {
				fmt.Printf("Error: %v\n", err)
				continue
			}
		}
		return input
	}
}
