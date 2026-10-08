# secstore
**secstore** is a lightweight Linux secrets manager that uses `age` encryption to securely store secrets on disk and decrypts them into a protected, non-swappable `tmpfs` filesystem at runtime. It supports initializing a local vault, adding and removing secrets, and hydrating encrypted secrets into memory for use by applications and services.
