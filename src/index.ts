import VirusTotal from './utils.js';
export default VirusTotal;

// Export types
export type { AnalysisResponse, AnalysisData, AnalysisAttributes, AnalysisStats, AnalysisResult, AnalysisCategory, AnalysisStatus } from './analysis/analysis.js';
export type { ScanUrlResponse, ScanUrlData, ScanUrlLinks, ScanUrlOptions } from './urls/scan-url.js';
