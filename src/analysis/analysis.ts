// https://docs.virustotal.com/reference/analysis

/**
 * Category of analysis result
 */
export type AnalysisCategory =
  | 'confirmed-timeout' // AV reached a timeout when analysing that file. Only returned in file analyses.
  | 'timeout' // AV reached a timeout when analysing that file.
  | 'failure' // AV failed when analysing this file. Only returned in file analyses.
  | 'harmless' // AV thinks the file is not malicious
  | 'undetected' // AV has no opinion about this file
  | 'suspicious' // AV thinks the file is suspicious
  | 'malicious' // AV thinks the file is malicious
  | 'type-unsupported'; // AV can't analyse that file. Only returned in file analyses.

/**
 * Status of the analysis
 */
export type AnalysisStatus =
  | 'completed' // the analysis is finished
  | 'queued' // the item is waiting to be analysed, the analysis object has empty results and stats
  | 'in-progress'; // the file is being analysed, the analysis object has partial analysis results and stats

/**
 * Individual analysis result from an engine
 */
export interface AnalysisResult {
  category: AnalysisCategory;
  engine_name: string;
  engine_update?: string; // Only returned in file analyses, in YYYYMMDD format
  engine_version?: string; // Only returned in file analyses
  method?: string;
  result: string | null; // Can be null if no verdict is available
}

/**
 * Statistics summary of analysis results
 */
export interface AnalysisStats {
  // File analysis specific stats
  'confirmed-timeout'?: number; // number of AV engines that reach a timeout when analysing that file
  failure?: number; // number of AV engines that fail when analysing that file
  'type-unsupported'?: number; // number of AV engines that don't support that type of file

  // Common stats
  harmless: number; // number of reports saying that is harmless
  malicious: number; // number of reports saying that is malicious
  suspicious: number; // number of reports saying that is suspicious
  timeout?: number; // number of timeouts when analysing this URL/file
  undetected: number; // number of reports saying that is undetected
}

/**
 * Analysis attributes representing the core data of an analysis
 */
export interface AnalysisAttributes {
  date: number; // Unix epoch UTC time (seconds)
  results: Record<string, AnalysisResult>; // dictionary with engine name as key and result as value
  stats: AnalysisStats; // summary of the results field
  status: AnalysisStatus; // analysis status
}

/**
 * Analysis data object representing an analysis of a URL or file submitted to VirusTotal
 */
export interface AnalysisData {
  attributes: AnalysisAttributes;
  id: string; // Analysis ID
  type: 'analysis'; // Type of the resource
}

/**
 * Complete Analysis response from VirusTotal API
 */
export interface AnalysisResponse {
  data: AnalysisData;
}
