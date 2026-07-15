import re
import math
import string
from datetime import datetime
from collections import Counter


class PasswordStrengthChecker:

    COMMON_PASSWORDS = {
        "password", "123456", "123456789", "qwerty",
        "admin", "welcome", "abc123", "password123",
        "letmein", "111111", "000000"
    }

    SEQUENCES = [
        "abcdefghijklmnopqrstuvwxyz",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "0123456789",
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm"
    ]

    def __init__(self, password):
        self.password = password
        self.score = 0
        self.feedback = []

    # ---------------- LENGTH ----------------
    def check_length(self):
        length = len(self.password)

        if length >= 16:
            self.score += 25

        elif length >= 12:
            self.score += 20

        elif length >= 8:
            self.score += 15

        else:
            self.feedback.append("Password should contain at least 8 characters.")

    # ---------------- UPPERCASE ----------------
    def check_uppercase(self):
        count = sum(c.isupper() for c in self.password)

        if count >= 2:
            self.score += 10
        elif count == 1:
            self.score += 5
        else:
            self.feedback.append("Include uppercase letters.")

    # ---------------- LOWERCASE ----------------
    def check_lowercase(self):
        count = sum(c.islower() for c in self.password)

        if count >= 2:
            self.score += 10
        elif count == 1:
            self.score += 5
        else:
            self.feedback.append("Include lowercase letters.")

    # ---------------- DIGITS ----------------
    def check_digits(self):
        digits = sum(c.isdigit() for c in self.password)

        if digits >= 3:
            self.score += 15
        elif digits >= 1:
            self.score += 8
        else:
            self.feedback.append("Add numbers.")

    # ---------------- SPECIAL CHARACTERS ----------------
    def check_symbols(self):
        symbols = sum(c in string.punctuation for c in self.password)

        if symbols >= 2:
            self.score += 15
        elif symbols == 1:
            self.score += 8
        else:
            self.feedback.append("Add special characters.")

    # ---------------- COMMON PASSWORD ----------------
    def check_common_password(self):

        if self.password.lower() in self.COMMON_PASSWORDS:
            self.feedback.append("This is a commonly used password.")
            self.score = 0

    # ---------------- REPEATED CHARACTERS ----------------
    def check_repeated(self):

        if re.search(r"(.)\1{2,}", self.password):
            self.feedback.append("Avoid repeated characters.")
            self.score -= 5

    # ---------------- SEQUENTIAL CHARACTERS ----------------
    def check_sequences(self):

        pwd = self.password.lower()

        for seq in self.SEQUENCES:

            for i in range(len(seq)-3):

                if seq[i:i+4].lower() in pwd:
                    self.feedback.append("Avoid sequential patterns (abcd,1234,qwerty).")
                    self.score -= 10
                    return

    # ---------------- CHARACTER VARIETY ----------------
    def character_variety(self):

        unique = len(set(self.password))

        if unique == len(self.password):
            self.score += 10
        else:
            self.score += 5

    # ---------------- ENTROPY ----------------
    def entropy(self):

        pool = 0

        if any(c.islower() for c in self.password):
            pool += 26

        if any(c.isupper() for c in self.password):
            pool += 26

        if any(c.isdigit() for c in self.password):
            pool += 10

        if any(c in string.punctuation for c in self.password):
            pool += 32

        if pool == 0:
            return 0

        entropy = len(self.password) * math.log2(pool)

        return round(entropy,2)

    # ---------------- PASSWORD STRENGTH ----------------
    def strength(self):

        if self.score >= 85:
            return "VERY STRONG"

        elif self.score >= 70:
            return "STRONG"

        elif self.score >= 50:
            return "MEDIUM"

        elif self.score >= 30:
            return "WEAK"

        return "VERY WEAK"

    # ---------------- LOG FILE ----------------
    def save_report(self):

        with open("password_log.txt","a") as file:

            file.write("\n---------------------------------\n")
            file.write(f"Time : {datetime.now()}\n")
            file.write(f"Password Length : {len(self.password)}\n")
            file.write(f"Score : {self.score}\n")
            file.write(f"Entropy : {self.entropy()} bits\n")
            file.write(f"Strength : {self.strength()}\n")

    # ---------------- MAIN EVALUATION ----------------
    def evaluate(self):

        self.check_common_password()
        self.check_length()
        self.check_uppercase()
        self.check_lowercase()
        self.check_digits()
        self.check_symbols()
        self.check_repeated()
        self.check_sequences()
        self.character_variety()

        print("\n" + "="*60)
        print("          PASSWORD SECURITY REPORT")
        print("="*60)

        print(f"Password Length  : {len(self.password)}")
        print(f"Entropy          : {self.entropy()} bits")
        print(f"Security Score   : {self.score}/100")
        print(f"Strength         : {self.strength()}")

        print("\nCharacter Count")

        counter = Counter(self.password)

        for char, count in counter.items():
            print(f"{repr(char)} : {count}")

        if self.feedback:
            print("\nSuggestions")

            for item in self.feedback:
                print("✔", item)

        else:
            print("\nExcellent Password!")

        self.save_report()

        print("\nReport saved in password_log.txt")


# ---------------- DRIVER ----------------

def main():

    print("="*65)
    print("        ADVANCED PASSWORD STRENGTH CHECKER")
    print("="*65)

    password = input("Enter Password : ")

    checker = PasswordStrengthChecker(password)

    checker.evaluate()


if __name__ == "__main__":
    main()