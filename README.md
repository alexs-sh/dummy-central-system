# Dummy Central System

Fast and dirty OCPP Central System implementation. It mostly for emulating CSRs
receiving and self-signed certificates sending.

# Supported messages

- BootNotification

- StatusNotification

- Heartbeat

- SignCertificate

- CertificateSigned

- StartTransaction

- MeterValues

- StopTransaction

- Authorize


# Build & run

```
cargo build
cargo run
```



