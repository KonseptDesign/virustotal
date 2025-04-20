import VirusTotal from '../src/utils.ts';
import * as dotenv from 'dotenv';

// Load environment variables from .env file
dotenv.config();

const apiKey = process.env.VIRUSTOTAL_API_KEY!;

if (!apiKey) {
  console.error('🔑 VIRUSTOTAL_API_KEY environment variable is not set');
  process.exit(1);
}

const vt = new VirusTotal(apiKey);

// Example 1: Scan a URL and get the analysis ID
async function scanUrl() {
  try {
    const url = 'https://github.com/KonseptDesign/virustotal';
    console.log(`🔍 Scanning URL: ${url}`);

    const scanResponse = await vt.scanUrl({ url });
    console.log('✅ Scan initiated successfully:');
    console.log(`🆔 Analysis ID: ${scanResponse.data.id}`);
    console.log(`🔗 Analysis URL: ${scanResponse.data.links.self}`);

    return scanResponse.data.id;
  } catch (error) {
    console.error('❌ Error scanning URL:', error);
  }
}

// Example 2: Get analysis results for a specific analysis ID
async function getAnalysisResults(analysisId: string) {
  try {
    console.log(`📊 Getting analysis results for ID: ${analysisId}`);

    const analysis = await vt.getAnalysis(analysisId);
    console.log(`🔄 Analysis status: ${analysis.data.attributes.status}`);

    // Print summary statistics
    const stats = analysis.data.attributes.stats;
    console.log('\n📋 Summary:');
    console.log(`✅ Harmless: ${stats.harmless}`);
    console.log(`⚠️ Malicious: ${stats.malicious}`);
    console.log(`⚠️ Suspicious: ${stats.suspicious}`);
    console.log(`❓ Undetected: ${stats.undetected}`);

    return analysis;
  } catch (error) {
    console.error('❌ Error getting analysis results:', error);
  }
}

// Example 3: Scan URL and wait for results (convenience method)
async function scanUrlAndWait() {
  try {
    const url = 'https://github.com/KonseptDesign/virustotal';
    console.log(`🔄 Scanning URL and waiting for results: ${url}`);

    console.log('⏳ This may take a moment...');
    const analysis = await vt.scanUrlAndWait(url);

    console.log('🎉 Analysis completed!');

    // Print summary statistics
    const stats = analysis.data.attributes.stats;
    console.log('\n📋 Summary:');
    console.log(`✅ Harmless: ${stats.harmless}`);
    console.log(`⚠️ Malicious: ${stats.malicious}`);
    console.log(`⚠️ Suspicious: ${stats.suspicious}`);
    console.log(`❓ Undetected: ${stats.undetected}`);

    return analysis;
  } catch (error) {
    console.error('❌ Error in scanUrlAndWait:', error);
  }
}

// Run the examples
async function runExamples() {
  console.log('🚀 Starting VirusTotal API examples...\n');
  
  // Example 1: Just scan the URL
  const analysisId = await scanUrl();
  console.log('\n📏 -----------------------------------\n');

  if (analysisId) {
    // Example 2: Get analysis results
    await getAnalysisResults(analysisId);
    console.log('\n📏 -----------------------------------\n');
  }

  // Example 3: Scan and wait for results
  await scanUrlAndWait();
  
  console.log('\n🏁 All examples completed successfully!');
}

runExamples().catch(error => console.error('❌ Error running examples:', error));
