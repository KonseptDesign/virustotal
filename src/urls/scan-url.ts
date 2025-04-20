// https://docs.virustotal.com/reference/scan-url

/**
 * Response links from a URL scan request
 */
export interface ScanUrlLinks {
  self: string; // URL to retrieve the analysis
}

/**
 * Data returned from a URL scan request
 */
export interface ScanUrlData {
  type: 'analysis';
  id: string; // Analysis ID
  links: ScanUrlLinks;
}

/**
 * Response from a URL scan request
 */
export interface ScanUrlResponse {
  data: ScanUrlData;
}

/**
 * Options for scanning a URL
 */
export interface ScanUrlOptions {
  url: string; // URL to scan
}
