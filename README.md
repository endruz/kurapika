# kurapika

- [kurapika](#kurapika)
  - [Install](#install)
  - [Usage](#usage)
  - [License](#license)

A software license tool。

## Install

```bash
cargo install kurapika
```

## Usage

```bash
# Help for the Generate Authorization Code command
$ kr-approver -h
kurapika 0.1.0
endruz <endruz@foxmail.com>
A software license tool

USAGE:
    kr-approver [OPTIONS] <FILE>

ARGS:
    <FILE>    Path to registration file

OPTIONS:
    -h, --help       Print help information
    -s, --show       Print authentication information
    -V, --version    Print version information
# Registration file structure
$ cat reg.toml
app_name = "XXX-service"
customer_name = "XXXX公司"
deploy_date = "2022-09-01"
expire_date = "2022-09-30"
# Generate authorization code
$ kr-approver reg.toml
Generate auth code successfully!
# Generate authorization code and display authentication information
# subject to actual output
$ kr-approver -s reg.toml
Generate auth code successfully!
Print authentication information:

app_name = "XXX-service"
customer_name = "XXXX公司"
deploy_date = "2022-09-01"
expire_date = "2022-09-30"
base_board_id = "****************"
cpu_id = "** ** ** ** ** ** ** **"
# Help for the Verify Authorization Code command
$ kr-checker -h
kurapika 0.1.0
endruz <endruz@foxmail.com>
A software license tool

USAGE:
    kr-checker

OPTIONS:
    -h, --help       Print help information
    -V, --version    Print version information
# Verify authorization code
$ kr-checker
Verification passed !!!
```

## License

Licensed under the [MIT License](./LICENSE).
