import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest';
import VirusTotal from './utils.js';
import type { ScanUrlResponse } from './urls/scan-url.js';
import type { AnalysisResponse } from './analysis/analysis.js';

// Mock data for tests
const mockScanResponse: ScanUrlResponse = {
  data: {
    type: 'analysis',
    id: 'test-analysis-id',
    links: {
      self: 'https://www.virustotal.com/api/v3/analyses/test-analysis-id'
    }
  }
};

const mockAnalysisResponse: AnalysisResponse = {
  data: {
    attributes: {
      date: 1591701032,
      results: {
        'Test-AV-1': {
          category: 'harmless',
          engine_name: 'Test-AV-1',
          method: 'blacklist',
          result: 'clean'
        },
        'Test-AV-2': {
          category: 'undetected',
          engine_name: 'Test-AV-2',
          method: 'blacklist',
          result: null
        }
      },
      stats: {
        harmless: 1,
        malicious: 0,
        suspicious: 0,
        undetected: 1
      },
      status: 'completed'
    },
    id: 'test-analysis-id',
    type: 'analysis'
  }
};

const mockInProgressAnalysisResponse: AnalysisResponse = {
  data: {
    attributes: {
      date: 1591701032,
      results: {
        'Test-AV-1': {
          category: 'harmless',
          engine_name: 'Test-AV-1',
          method: 'blacklist',
          result: 'clean'
        }
      },
      stats: {
        harmless: 1,
        malicious: 0,
        suspicious: 0,
        undetected: 0
      },
      status: 'in-progress'
    },
    id: 'test-analysis-id',
    type: 'analysis'
  }
};

// Mock fetch globally
vi.stubGlobal('fetch', vi.fn());

describe('VirusTotal', () => {
  let vt: VirusTotal;
  const mockApiKey = 'test-api-key';
  
  beforeEach(() => {
    vt = new VirusTotal(mockApiKey);
    vi.resetAllMocks();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  test('constructor should throw error if API key is not provided', () => {
    expect(() => new VirusTotal('')).toThrow('API key is required');
  });

  test('constructor should set API key and base URL', () => {
    const customBaseUrl = 'https://custom-api.virustotal.com/api/v3';
    const vtWithCustomUrl = new VirusTotal(mockApiKey, customBaseUrl);
    
    // Testing private properties indirectly through method behavior
    // @ts-ignore - Accessing private property for testing
    expect(vtWithCustomUrl.apiKey).toBe(mockApiKey);
    // @ts-ignore - Accessing private property for testing
    expect(vtWithCustomUrl.baseUrl).toBe(customBaseUrl);
  });

  describe('scanUrl', () => {
    test('should make a POST request to scan a URL', async () => {
      const mockResponse = new Response(JSON.stringify(mockScanResponse), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
      
      // Mock the fetch call
      vi.mocked(fetch).mockResolvedValueOnce(mockResponse);

      const result = await vt.scanUrl({ url: 'https://example.com' });
      
      // Verify fetch was called with correct arguments
      expect(fetch).toHaveBeenCalledTimes(1);
      expect(fetch).toHaveBeenCalledWith(
        'https://www.virustotal.com/api/v3/urls',
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'x-apikey': mockApiKey
          })
        })
      );
      
      // Verify result
      expect(result).toEqual(mockScanResponse);
    });

    test('should throw an error if the API request fails', async () => {
      const mockResponse = new Response(JSON.stringify({ error: 'API error' }), {
        status: 400,
        statusText: 'Bad Request'
      });
      
      vi.mocked(fetch).mockResolvedValueOnce(mockResponse);

      await expect(vt.scanUrl({ url: 'https://example.com' }))
        .rejects
        .toThrow('VirusTotal API error: 400 Bad Request');
    });
  });

  describe('getAnalysis', () => {
    test('should make a GET request to retrieve analysis results', async () => {
      const mockResponse = new Response(JSON.stringify(mockAnalysisResponse), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
      
      vi.mocked(fetch).mockResolvedValueOnce(mockResponse);

      const result = await vt.getAnalysis('test-analysis-id');
      
      // Verify fetch was called with correct arguments
      expect(fetch).toHaveBeenCalledTimes(1);
      expect(fetch).toHaveBeenCalledWith(
        'https://www.virustotal.com/api/v3/analyses/test-analysis-id',
        expect.objectContaining({
          method: 'GET',
          headers: expect.objectContaining({
            'x-apikey': mockApiKey
          })
        })
      );
      
      // Verify result
      expect(result).toEqual(mockAnalysisResponse);
    });

    test('should throw an error if the API request fails', async () => {
      const mockResponse = new Response(JSON.stringify({ error: 'API error' }), {
        status: 404,
        statusText: 'Not Found'
      });
      
      vi.mocked(fetch).mockResolvedValueOnce(mockResponse);

      await expect(vt.getAnalysis('invalid-id'))
        .rejects
        .toThrow('VirusTotal API error: 404 Not Found');
    });
  });

  describe('scanUrlAndWait', () => {
    test('should scan URL and poll until analysis is completed', async () => {
      // Track the number of calls to fetch
      let callCount = 0;
      
      // Setup fetch mock to return different responses based on call count
      vi.mocked(fetch).mockImplementation((url, options) => {
        callCount++;
        
        // First call is the scan request
        if (options?.method === 'POST') {
          return Promise.resolve(
            new Response(JSON.stringify(mockScanResponse), {
              status: 200,
              headers: { 'Content-Type': 'application/json' }
            })
          );
        }
        
        // Second call (first analysis check) returns in-progress
        if (callCount === 2) {
          return Promise.resolve(
            new Response(JSON.stringify(mockInProgressAnalysisResponse), {
              status: 200,
              headers: { 'Content-Type': 'application/json' }
            })
          );
        }
        
        // Third call (second analysis check) returns completed
        return Promise.resolve(
          new Response(JSON.stringify(mockAnalysisResponse), {
            status: 200,
            headers: { 'Content-Type': 'application/json' }
          })
        );
      });

      // Mock setTimeout to execute immediately
      vi.spyOn(global, 'setTimeout').mockImplementation((callback: any) => {
        callback();
        return 0 as any;
      });

      const result = await vt.scanUrlAndWait('https://example.com', 100, 5);
      
      // Verify fetch was called 3 times (scan + 2 analysis checks)
      expect(fetch).toHaveBeenCalledTimes(3);
      
      // Verify the final result is the completed analysis
      expect(result).toEqual(mockAnalysisResponse);
    });

    test('should throw an error if max attempts are reached', async () => {
      // Setup fetch mock to return different responses for each call
      vi.mocked(fetch).mockImplementation((url, options) => {
        // First call is the scan request
        if (options?.method === 'POST') {
          return Promise.resolve(
            new Response(JSON.stringify(mockScanResponse), {
              status: 200,
              headers: { 'Content-Type': 'application/json' }
            })
          );
        }
        
        // All other calls are for analysis and should return in-progress
        return Promise.resolve(
          new Response(JSON.stringify(mockInProgressAnalysisResponse), {
            status: 200,
            headers: { 'Content-Type': 'application/json' }
          })
        );
      });

      // Mock setTimeout to execute immediately
      vi.spyOn(global, 'setTimeout').mockImplementation((callback: any) => {
        callback();
        return 0 as any;
      });

      // Set max attempts to 3
      await expect(vt.scanUrlAndWait('https://example.com', 100, 3))
        .rejects
        .toThrow('Analysis did not complete within 3 attempts');
      
      // Verify fetch was called 4 times (scan + 3 analysis checks)
      expect(fetch).toHaveBeenCalledTimes(4);
    });
  });
});
