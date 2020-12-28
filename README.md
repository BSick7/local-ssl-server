# local-ssl-server

This program provides SSL termination to another server.
This is a very simple way to achieve HTTPS on your local machine without changing any services.

## Options

The following are default options:
- `port=8443`
- `upstream=http://localhost:8080`
- `cert=localhost.crt`
- `key=localhost.key`.

This will serve HTTPS traffic @ `https://localhost:8443` proxying to `http://localhost:8080`.

If `--cert` and `--key` files are not found when starting, this program will generate self-signed certificates and use them.

NOTE: If a client reaching this server verifies the certificate, you will need to ensure the generated certificate is in your trust store.

## SSL Certificates

This program will generate self-signed certificates; however, it's best to use [`mkcert`](https://github.com/FiloSottile/mkcert#installation) instead.
This tool manages a root CA on your computer and allows you to generate local-friendly certificates (`host.docker.internal`, `localhost`, etc.).