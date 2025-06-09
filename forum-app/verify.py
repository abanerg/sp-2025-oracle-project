#!/usr/bin/env python3
import subprocess
import os

def main():
    try:
        input("Press Enter to start the verification process...\n")

        user_input = input("Enter your secret cookie: ")

        with open("forum-app/cookie.txt", "w") as f:
            f.write(user_input)

        script_path = os.path.join(os.path.dirname(__file__), "run.sh")
        result = subprocess.run(["bash", script_path], check=True)

        print("VERIFICATION PASSED")

    except subprocess.CalledProcessError as e:
        print(f"Script failed with exit code {e.returncode}")
    except KeyboardInterrupt:
        print("\nInterrupted by user")
    except Exception as e:
        print(f"Unexpected error: {e}")

if __name__ == "__main__":
    main()
