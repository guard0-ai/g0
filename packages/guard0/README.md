<p align="center">
  <img src="https://raw.githubusercontent.com/guard0-ai/g0/main/assets/logo.png" alt="Guard0" width="200">
</p>

<h1 align="center">Guard0 — The Control Layer for AI Agents</h1>

<p align="center">
  <a href="https://www.npmjs.com/package/@guard0/g0"><img src="https://img.shields.io/npm/v/@guard0/g0.svg" alt="npm version"></a>
  <a href="https://nodejs.org"><img src="https://img.shields.io/badge/node-%3E%3D20-brightgreen.svg" alt="Node.js >= 20"></a>
  <a href="https://owasp.org/www-project-agentic-security/"><img src="https://img.shields.io/badge/OWASP-Agentic%20Top%2010-orange.svg" alt="OWASP Agentic"></a>
</p>

This is the convenience package for **[Guard0](https://guard0.ai)** (`@guard0/g0`). It lets you install and run Guard0 without the scoped package name.

## Install

```bash
npm install -g guard0
```

## Usage

```bash
guard0 scan ./my-agent               # Security assessment
guard0 scan https://github.com/org/repo  # Remote repo scan
guard0 inventory .                    # AI Bill of Materials
guard0 test --target http://localhost:3000/api/chat  # Adversarial testing
guard0 endpoint                       # Developer machine assessment
guard0 detect                         # AI tool & MDM detection
```

The `g0` shorthand also works:

```bash
g0 scan .
```

## Documentation

See the full documentation at **[@guard0/g0](https://github.com/guard0-ai/g0)**.
