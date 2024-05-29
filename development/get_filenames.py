import os

for root, dirs, files in os.walk("custom_test_alerts/"):
    for file in files:
        if file.endswith(".toml"):
            print(file)
