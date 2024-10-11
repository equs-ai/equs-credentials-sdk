# ASDK wrappers for Node.js

## Prerequisites

Ensure that the following tools are installed on your machine:

- [Node.js](https://nodejs.org/) (version >= v10.16.0+)
- [npm](https://www.npmjs.com/) (version >= v11.8.0+)
- [cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html) (version >= 12.0.0)

## Installation

Follow these steps to install Node.js wrapped ASDK as dependency to your Node.js project:

1. **Add dependency to your package.json**:
   ```
   npm install agent-sdk@git+ssh://git@git.slock.it/equstng/agent-sdk/agent-sdk
   ```
   ```
   yarn add agent-sdk@git+ssh://git@git.slock.it/equstng/agent-sdk/agent-sdk
   ```
   in case of dev version with features available use
   ```
   NODE_ENV=development npm install agent-sdk@git+ssh://git@git.slock.it/equstng/agent-sdk/agent-sdk
   ```
   ```
   NODE_ENV=development yarn add agent-sdk@git+ssh://git@git.slock.it/equstng/agent-sdk/agent-sdk
   ```
   You can specify package alias instead of `agend-sdk`

2. **Default postinstall**:
   Package contains default post install scripts that builds wrappers and make it possible for you to import them and
   use.
   You only need installed npm & cargo for it to run successfully.

## Usage

After installation and its post install script you can import package in both es modules & commonjs syntax.
