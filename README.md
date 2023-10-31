# One-Time Passwords
[![GoDoc](https://godoc.org/github.com/sshilin/otp?status.svg)](https://godoc.org/github.com/sshilin/otp)

Package otp implements the RFC 4226 (HOTP) and RFC 6238 (TOTP) standards for one-time password generation and validation. It provides functions to generate and validate HMAC-Based and Time-Based One-Time Passwords using a shared secret key.

## Install

```sh
go get github.com/sshilin/otp
```

## Usage
```go
key := []byte("secret")

hotp := otp.NewHotp()
totp := otp.NewTotp()

code := hotp.Generate(key, totp.At(time.Now()))

isValid := hotp.Validate(key, code, totp.At(time.Now()))
```

## Use with Google Authenticator
The example generates QR-code for registering a demo service in TOTP mode and then prompts codes from the authenticator.
```go
func main() {
	key := make([]byte, 20)
	rand.Read(key)

	hotp := otp.NewHotp()
	totp := otp.NewTotp()

	secret := strings.TrimRight(base32.StdEncoding.EncodeToString(key), "=")
	uri := fmt.Sprintf("otpauth://totp/demo:example?secret=%s&issuer=demo", secret)

	qrterminal.Generate(uri, qrterminal.M, os.Stdout)

	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("Code: ")
		text, _ := reader.ReadString('\n')
		code := strings.TrimSpace(text)
		isValid := hotp.Validate(key, code, totp.At(time.Now()))
		fmt.Println("Is valid:", isValid)
	}
}
```
