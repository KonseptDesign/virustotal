# @konseptdesign/virustotal

<a href="https://www.npmjs.com/package/@konseptdesign/virustotal"><img src="https://img.shields.io/npm/v/@konseptdesign/virustotal?label=latest" alt="npm version" /></a>
<a href="https://github.com/KonseptDesign/virustotal/blob/main/LICENSE" rel="nofollow"><img src="https://img.shields.io/npm/l/@konseptdesign/virustotal" alt="license" /></a>
<a href="https://github.com/KonseptDesign/virustotal/actions?query=branch%3Amain" rel="nofollow"><img src="https://github.com/KonseptDesign/virustotal/actions/workflows/main.yml/badge.svg?event=push&branch=main" alt="build status" /></a>
<a href="https://github.com/KonseptDesign/virustotal" rel="nofollow"><img src="https://img.shields.io/github/stars/KonseptDesign/virustotal" alt="stars"></a>

A TypeScript client for the VirusTotal API v3.

## Installation

```bash
# npm
npm install @konseptdesign/virustotal

# yarn
yarn add @konseptdesign/virustotal

# pnpm
pnpm add @konseptdesign/virustotal
```

## Usage

```typescript
import VirusTotal from '@konseptdesign/virustotal';

// Initialize with your API key
const vt = new VirusTotal('YOUR_API_KEY');

// Method 1: Scan a URL and get the analysis ID
const scanResponse = await vt.scanUrl({ url: 'https://example.com' });
const analysisId = scanResponse.data.id;
console.log(`Analysis ID: ${analysisId}`);

// Method 2: Get analysis results for a specific analysis ID
const analysis = await vt.getAnalysis(analysisId);
console.log(`Status: ${analysis.data.attributes.status}`);
console.log(`Harmless detections: ${analysis.data.attributes.stats.harmless}`);
console.log(`Malicious detections: ${analysis.data.attributes.stats.malicious}`);

// Method 3: Scan URL and wait for results (convenience method)
const results = await vt.scanUrlAndWait('https://example.com');
console.log(`Malicious detections: ${results.data.attributes.stats.malicious}`);
```

## Features

- TypeScript support with comprehensive type definitions
- Modern ESM package
- URL scanning and analysis
- Polling mechanism to wait for analysis completion

## Development

### Prerequisites

- Node.js (latest LTS recommended)
- pnpm

### Setup

```bash
# Install dependencies
pnpm install
```

### Commands

```bash
# Build the package
pnpm build

# Run tests
pnpm test

# Format code
pnpm prettier

# Run CI checks locally
pnpm run:ci

# Publish a new version (maintainers only)
pnpm local-release
```

## License

MIT © [Alex Marinov](https://konsept.design)
