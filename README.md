
# Java SSL Test
This is a CLI utility that is used to test the connectivity between your JDK/JRE to an SSL endpoint. This outputs SSL information like the Ciphers, Protocol, prints Certificate details and it is fully customizable using CLI.
This is based upon [ssltest](https://github.com/ChristopherSchultz/ssltest). Unlike, [ssltest](https://github.com/ChristopherSchultz/ssltest), this is multi threaded and is supposed to be `10x` times faster to produce results. 


[![GitHub version](https://badge.fury.io/gh/reflexdemon%2Fjava-ssl-test.png)](http://badge.fury.io/gh/reflexdemon%2Fjava-ssl-test)
[![npm version](https://badge.fury.io/js/java-ssltest-cli.png)](http://badge.fury.io/js/java-ssltest-cli)
[![Build status](https://ci.appveyor.com/api/projects/status/kper4nraqsbrhui6/branch/master?svg=true)](https://ci.appveyor.com/project/reflexdemon/java-ssl-test/branch/master)

## Usage

```
Usage: javassltest [opts] host[:port]

Options:
-sslprotocol                 Sets the SSL/TLS protocol to be used (e.g. SSL, TLS, SSLv3, TLSv1.2, etc.)
-enabledprotocols protocols  Sets individual SSL/TLS ptotocols that should be enabled
-ciphers cipherspec          A comma-separated list of SSL/TLS ciphers

-keystore                    Sets the key store for connections (for TLS client certificates)
-keystoretype type           Sets the type for the key store
-keystorepassword pass       Sets the password for the key store
-keystoreprovider provider   Sets the crypto provider for the key store

-truststore                  Sets the trust store for connections
-truststoretype type         Sets the type for the trust store
-truststorepassword pass     Sets the password for the trust store
-truststorealgorithm alg     Sets the algorithm for the trust store
-truststoreprovider provider Sets the crypto provider for the trust store
-crlfilename                 Sets the CRL filename to use for the trust store

-check-certificate           Checks certificate trust (default: false)
-no-check-certificate        Ignores certificate errors (default: true)
-verify-hostname             Verifies certificate hostname (default: false)
-no-verify-hostname          Ignores hostname mismatches (default: true)

-showsslerrors               Show SSL/TLS error details
-showhandshakeerrors         Show SSL/TLS handshake error details
-showerrors                  Show all connection error details
-hiderejects                 Only show protocols/ciphers which were successful
-showcerts                   Shows some basic Certificate details

-h -help --help              Shows this help message

```


## Installation

To make the distribution seamless, we have used Node Package Manager (NPM) based approach. That will require you to install the application using NPM.


### Prerequisites


1. NodeJS
2. Probably a pre-installed JDK/JRE on your computer.

Runs on any platform that supports requirements including Mac, Windows, and Linux.


### Install the application

To install the CLI tool just run  the following command.

```
npm i -g java-ssltest-cli
```


#### Troubleshooting on Permissions
If you are running into permission issues on installing global application please refer to this link. https://docs.npmjs.com/getting-started/fixing-npm-permissions



## Issues

### Common Issues #1

One of the known issue is some of the node versions that do not work and throws errors. In that case please consider the following,

Downgrade the Node Version to the previous stable LTS (Long Term Support) version of nodejs.

Steps to be followed,
1. Install NVM: https://github.com/creationix/nvm/blob/master/README.md#installation
2. Install the stable version of nodjs using: `nvm install v8.11.1`
3. Install your cli tool: `npm i -g <your-app-name>`

### Common Issues #2

The other issue could be your JDK or JRE are conflicting on the path and that is causing the mixed runtime and Java SSL API is not able to use the correct runtime values.

Steps to be followed,
1. Set the `JAVA_HOME` correctly

On linux/unix based systems,

```
export JAVA_HOME=</path/to/your/java/home>
export PATH=$JAVA_HOME/bin:$PATH
```

On Windows,
```
set JAVA_HOME=</path/to/your/java/home>
set PATH=%JAVA_HOME%\bin;%PATH%
```

2. Now run your command

If the above options did not help and you wish to report issues please visit https://github.com/reflexdemon/java-ssl-test/issues and log your issues with the following details,

1. `java -version` output
2. `javac -version` output
3. `npm -v` output
4. `node -v` output

## Thanks
To make this happen I will have to thank the below people and their creations.
1. [Christopher Schultz](https://github.com/ChristopherSchultz) for [ssltest](https://github.com/ChristopherSchultz/ssltest)
2. [Steve Hannah](https://github.com/shannah) for [jdeploy](https://github.com/shannah/jdeploy).

## Licence

MIT