# PasswordBuilder Tool for Node.js

[![tests](https://github.com/aronep6/password-builder/actions/workflows/feat-tests.yml/badge.svg)](https://github.com/aronep6/password-builder/actions/workflows/feat-tests.yml)

[![audit](https://github.com/aronep6/password-builder/actions/workflows/audit-check.yml/badge.svg)](https://github.com/aronep6/password-builder/actions/workflows/audit-check.yml)

The PasswordBuilder library is a simple utility for securely hashing and verifying passwords using cryptographic hashing algorithms. It provides a way to hash passwords with a user-provided salt and verify passwords against hashed values. This library is intended to be used in Node.js applications and relies on the `node:crypto` module for cryptographic operations.

## Installation

To use PasswordBuilder, you need to have Node.js installed on your system. If you don't have it installed, you can download it from the official website: [Node.js](https://nodejs.org/).

To install the library in your Node.js project, you can use npm or yarn:

```bash
npm install password-builder
# or
yarn add password-builder
```

## Usage

To use PasswordBuilder, you need to import it and use the provided methods for hashing and verifying passwords. The library exports a default class `PasswordBuilder` with two static methods: `hash` and `verify`.

### Importing the library

```javascript
import PasswordBuilder from "password-builder";
```

or get only the methods you need

```javascript
import { hash, verify, generateSalt } from "password-builder";
```

### Hashing a password

The `hash` method is used to hash a given password with a provided salt. It returns the hashed password as a string.

```javascript
const password = "mySecurePassword";
const salt = "a-random-salt-value";

const hashedPassword = PasswordBuilder.hash(password, salt);
// or
const hashedPassword = hash(password, salt);

console.log(hashedPassword); // Output: 'a-random-salt-value.7ef0dab7e6a6...'
```

#### Generating a random salt value

You can also create a random salt value using the `generateSalt` method:

```javascript
const password = "mySecurePassword";

const salt = PasswordBuilder.generateSalt();
// or
const salt = generateSalt();

const hashedPassword = PasswordBuilder.hash(password, salt);
```

This way is more secure than using a static salt value. We recommend using a random salt value for each password to enhance security.

You can also pass an optional configuration object to specify the hashing algorithm and the output encoding, to override the default values (SHA-512 for the hashing algorithm and hexadecimal for the output encoding).

```javascript
const configuration = {
  hashAlgorithm: "sha256", // or 'sha512' (default)
  hashDigest: "base64", // or 'base64url', 'hex', 'binary' (default is 'hex')
};

const hashedPassword = PasswordBuilder.hash(password, salt, configuration);
// or
const hashedPassword = hash(password, salt, configuration);

console.log(hashedPassword); // Output: 'a-random-salt-value.u2tdtrRv...'
```

### Custom salt hash separator

By default, the salt and the hashed password are separated by a dot (`.`). You can change this separator by passing a custom separator to the `hash` method, with the `inSeparator` property of the configuration object:

```javascript
const hashedPassword = PasswordBuilder.hash(password, salt, {
  inSeparator: "-",
});
```

### Verifying a password

The `verify` method is used to verify a password against a hashed password. It returns `true` if the password matches the hash, and `false` otherwise.

```javascript
const password = "mySecurePassword";
const hashedPassword = "a-random-salt-value.7ef0dab7e6a6...";

const isMatch = PasswordBuilder.verify(password, hashedPassword);
// or
const isMatch = verify(password, hashedPassword);

console.log(isMatch); // Output: true
```

You can also pass the same configuration object used during hashing to ensure the correct hashing algorithm and encoding are used during the verification process.

```javascript
const configuration = {
  hashAlgorithm: "sha256",
  hashDigest: "base64",
};

const isMatch = PasswordBuilder.verify(password, hashedPassword, configuration);
// or
const isMatch = verify(password, hashedPassword, configuration);

console.log(isMatch); // Output: true
```

## Hash & Verify configuration

The `PasswordBuilder` class accepts an optional configuration object to specify the hashing algorithm and the output encoding. The configuration object has the following properties:

- `hashAlgorithm`: The hashing algorithm to use. The default value is `sha512`. The supported values are `sha256` and `sha512`.

- `hashDigest`: The output encoding to use. The default value is `hex`. The supported values are `base64`, `base64url`, `hex`, and `binary`.

- `inSeparator`: The separator to use between the salt and the hashed password. The default value is `.`.

## API

### PasswordBuilder.hash(password, salt, [configuration])

Hashes a given password with a provided salt and returns the hashed password as a string.

#### Parameters

- `password`: The password to hash.
- `salt`: The salt value to use for hashing.
- `configuration`: An optional configuration object to specify the hashing algorithm and the output encoding. The default values are `sha512` for the hashing algorithm and `hex` for the output encoding.

#### Returns

The hashed password as a string.

### PasswordBuilder.verify(password, hashedPassword, [configuration])

Verifies a password against a hashed password and returns `true` if the password matches the hash, and `false` otherwise.

#### Parameters

- `password`: The password to verify.
- `hashedPassword`: The hashed password to verify against.
- `configuration`: An optional configuration object to specify the hashing algorithm and the output encoding. The default values are `sha512` for the hashing algorithm and `hex` for the output encoding.

#### Returns

`true` if the password matches the hash, and `false` otherwise.

### PasswordBuilder.generateSalt()

Generates a random salt value and returns it as a string.

#### Returns

The generated salt value as a string.

## Full example

```javascript
import { generateSalt, hash, verify } from "password-builder";

const password = "mySecurePassword";

// Generate a random salt value
const salt = generateSalt();

// Hash the password
const hashedPassword = hash(password, salt, {
  hashAlgorithm: "sha512",
  hashDigest: "hex",
  inSeparator: "-",
});

// ... Store the hashed password in the database

// Later ... Verify the password
const isMatch = verify(password, hashedPassword, {
  hashAlgorithm: "sha512",
  hashDigest: "hex",
  inSeparator: "-",
});

console.log(isMatch); // Output: true
```

## Important Notes

- Always use a secure and unique salt value for each password to enhance security.
- Ensure that the `node:crypto` module is available in your Node.js environment.
- Do not store plain-text passwords; always store the hashed values.
- Keep the library up-to-date and use the latest version to benefit from potential security updates.

## License

This library is open-source and distributed under the [MIT License](https://github.com/aronep6/password-builder/blob/master/LICENCE). Feel free to contribute to the project or report any issues on the [GitHub repository](https://github.com/aronep6/password-builder).
