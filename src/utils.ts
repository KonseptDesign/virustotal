import type { AnalysisResponse } from './analysis/analysis.js';
import type { ScanUrlOptions, ScanUrlResponse } from './urls/scan-url.js';

/**
 * Base URL for the VirusTotal API v3
 */
const API_BASE_URL = 'https://www.virustotal.com/api/v3';

/**
 * VirusTotal API client
 */
export default class VirusTotal {
  private apiKey: string;
  private baseUrl: string;

  /**
   * Creates a new VirusTotal API client
   * @param apiKey Your VirusTotal API key
   * @param baseUrl Optional custom base URL for the API
   */
  constructor(apiKey: string, baseUrl: string = API_BASE_URL) {
    if (!apiKey) {
      throw new Error('API key is required');
    }
    
    this.apiKey = apiKey;
    this.baseUrl = baseUrl;
  }

  /**
   * Common headers for all API requests
   */
  private get headers() {
    return {
      'x-apikey': this.apiKey,
      'Content-Type': 'application/x-www-form-urlencoded',
    };
  }

  /**
   * Scans a URL using VirusTotal
   * @param options Options containing the URL to scan
   * @returns A promise that resolves to the scan response
   */
  async scanUrl(options: ScanUrlOptions): Promise<ScanUrlResponse> {
    const url = `${this.baseUrl}/urls`;
    const formData = new URLSearchParams();
    formData.append('url', options.url);

    const response = await fetch(url, {
      method: 'POST',
      headers: this.headers,
      body: formData,
    });

    if (!response.ok) {
      throw new Error(`VirusTotal API error: ${response.status} ${response.statusText}`);
    }

    return await response.json() as ScanUrlResponse;
  }

  /**
   * Gets analysis results for a specific analysis ID
   * @param analysisId The analysis ID to retrieve results for
   * @returns A promise that resolves to the analysis response
   */
  async getAnalysis(analysisId: string): Promise<AnalysisResponse> {
    const url = `${this.baseUrl}/analyses/${analysisId}`;
    
    const response = await fetch(url, {
      method: 'GET',
      headers: this.headers,
    });

    if (!response.ok) {
      throw new Error(`VirusTotal API error: ${response.status} ${response.statusText}`);
    }

    return await response.json() as AnalysisResponse;
  }

  /**
   * Convenience method to scan a URL and wait for the analysis to complete
   * @param url The URL to scan
   * @param pollInterval Interval in milliseconds to poll for results (default: 2000)
   * @param maxAttempts Maximum number of polling attempts (default: 10)
   * @returns A promise that resolves to the analysis response
   */
  async scanUrlAndWait(url: string, pollInterval = 2000, maxAttempts = 10): Promise<AnalysisResponse> {
    // First, scan the URL
    const scanResponse = await this.scanUrl({ url });
    const analysisId = scanResponse.data.id;
    
    // Then poll for results
    let attempts = 0;
    while (attempts < maxAttempts) {
      const analysis = await this.getAnalysis(analysisId);
      
      // If analysis is completed, return it
      if (analysis.data.attributes.status === 'completed') {
        return analysis;
      }
      
      // Otherwise, wait and try again
      await new Promise(resolve => setTimeout(resolve, pollInterval));
      attempts++;
    }
    
    throw new Error(`Analysis did not complete within ${maxAttempts} attempts`);
  }
}
