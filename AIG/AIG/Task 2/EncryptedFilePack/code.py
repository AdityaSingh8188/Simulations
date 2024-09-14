import zipfile

def attempt_extract(zf_handle, password):
    try:
        zf_handle.extractall(pwd=password)
        print("[+] Password found: ",password.decode())
        return True
    except:
        pass
    return False

def main():
    with zipfile.ZipFile('enc.zip') as zf:
        with open('rockyou.txt', 'rb') as f:
            for password in f:
                password = password.strip()
                if attempt_extract(zf, password):
                    break
                else:
                    print("[-] Incorrect password:",password.decode())
            else:
                print("[-] Password not found in list")
if __name__ == "__main__":
    main()