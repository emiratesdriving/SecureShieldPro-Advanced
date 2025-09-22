import React, { useState, useEffect, useCallback } from 'react';
import {
  CloudArrowUpIcon,
  DocumentTextIcon,
  ShieldCheckIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  XCircleIcon,
  ClockIcon,
  EyeIcon,
  TrashIcon,
  ArrowDownTrayIcon,
  BoltIcon,
  CpuChipIcon,
  MagnifyingGlassIcon,
  BeakerIcon,
  ChartBarIcon
} from '@heroicons/react/24/outline';

interface SecurityFinding {
  id: string;
  type: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational';
  confidence: number;
  file_path: string;
  line_number?: number;
  code_snippet?: string;
  cwe_id?: string;
  cvss_score?: number;
  remediation?: string;
  references: string[];
  false_positive: boolean;
}

interface AnalysisReport {
  id: string;
  filename: string;
  file_hash: string;
  file_size: number;
  analysis_type: string[];
  status: 'pending' | 'analyzing' | 'completed' | 'failed';
  created_at: string;
  completed_at?: string;
  execution_time?: number;
  findings_count: number;
  findings: SecurityFinding[];
  severity_breakdown: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    informational: number;
  };
  ai_summary?: string;
  remediation_suggestions: string[];
  metadata: Record<string, any>;
}

interface AnalysisMetrics {
  total_reports: number;
  completed_reports: number;
  failed_reports: number;
  success_rate: number;
  average_execution_time: number;
  total_findings: number;
  severity_breakdown: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    informational: number;
  };
  ai_models_status: Record<string, number>;
}

const EnhancedSecurityAnalysis: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'upload' | 'reports' | 'dashboard'>('dashboard');
  const [reports, setReports] = useState<AnalysisReport[]>([]);
  const [selectedReport, setSelectedReport] = useState<AnalysisReport | null>(null);
  const [metrics, setMetrics] = useState<AnalysisMetrics | null>(null);
  const [loading, setLoading] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState<Record<string, number>>({});

  // Upload states
  const [selectedFiles, setSelectedFiles] = useState<FileList | null>(null);
  const [analysisTypes, setAnalysisTypes] = useState<string[]>([
    'static_analysis',
    'dependency_scan',
    'secret_detection',
    'malware_scan'
  ]);

  // Load initial data
  useEffect(() => {
    loadDashboardData();
    loadReports();
    
    // Real-time updates
    const interval = setInterval(() => {
      loadDashboardData();
      loadReports();
    }, 10000); // Update every 10 seconds

    return () => clearInterval(interval);
  }, []);

  const loadDashboardData = async () => {
    try {
      const response = await fetch('/api/v1/analysis/metrics');
      const data = await response.json();
      if (data.status === 'success') {
        setMetrics(data.metrics);
      }
    } catch (error) {
      console.error('Failed to load dashboard data:', error);
    }
  };

  const loadReports = async () => {
    try {
      const response = await fetch('/api/v1/analysis/reports?limit=50');
      const data = await response.json();
      if (data.status === 'success') {
        setReports(data.reports);
      }
    } catch (error) {
      console.error('Failed to load reports:', error);
    }
  };

  const handleFileUpload = async () => {
    if (!selectedFiles || selectedFiles.length === 0) return;

    setUploading(true);
    const uploadResults = [];

    try {
      for (let i = 0; i < selectedFiles.length; i++) {
        const file = selectedFiles[i];
        const formData = new FormData();
        formData.append('file', file);
        formData.append('analysis_types', analysisTypes.join(','));
        formData.append('description', `Uploaded file: ${file.name}`);

        // Update progress
        setUploadProgress(prev => ({ ...prev, [file.name]: 0 }));

        try {
          const response = await fetch('/api/v1/analysis/upload', {
            method: 'POST',
            body: formData,
            // Note: In a real implementation, you'd want to track upload progress
          });

          const result = await response.json();
          
          if (result.status === 'uploaded') {
            uploadResults.push({
              filename: file.name,
              success: true,
              analysis_id: result.analysis_id
            });
            setUploadProgress(prev => ({ ...prev, [file.name]: 100 }));
          } else {
            uploadResults.push({
              filename: file.name,
              success: false,
              error: result.detail || 'Upload failed'
            });
          }
        } catch (error) {
          uploadResults.push({
            filename: file.name,
            success: false,
            error: error instanceof Error ? error.message : 'Upload failed'
          });
        }
      }

      // Clear upload state
      setSelectedFiles(null);
      setUploadProgress({});
      
      // Refresh reports
      loadReports();
      loadDashboardData();

    } catch (error) {
      console.error('Upload failed:', error);
    } finally {
      setUploading(false);
    }
  };

  const handleReportSelect = async (reportId: string) => {
    try {
      setLoading(true);
      const response = await fetch(`/api/v1/analysis/reports/${reportId}`);
      const data = await response.json();
      
      if (data.status === 'success') {
        setSelectedReport(data.report);
      }
    } catch (error) {
      console.error('Failed to load report details:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteReport = async (reportId: string) => {
    try {
      setLoading(true);
      const response = await fetch(`/api/v1/analysis/reports/${reportId}`, {
        method: 'DELETE'
      });
      
      if (response.ok) {
        setReports(prev => prev.filter(r => r.id !== reportId));
        if (selectedReport?.id === reportId) {
          setSelectedReport(null);
        }
        loadDashboardData();
      }
    } catch (error) {
      console.error('Failed to delete report:', error);
    } finally {
      setLoading(false);
    }
  };

  const toggleFalsePositive = async (reportId: string, findingId: string, isFalsePositive: boolean) => {
    try {
      const response = await fetch(
        `/api/v1/analysis/reports/${reportId}/findings/${findingId}/false-positive`,
        {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ is_false_positive: isFalsePositive })
        }
      );
      
      if (response.ok && selectedReport) {
        // Update the finding in the selected report
        const updatedReport = {
          ...selectedReport,
          findings: selectedReport.findings.map(f =>
            f.id === findingId ? { ...f, false_positive: isFalsePositive } : f
          )
        };
        setSelectedReport(updatedReport);
      }
    } catch (error) {
      console.error('Failed to update finding:', error);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-600 bg-red-100 border-red-200';
      case 'high': return 'text-orange-600 bg-orange-100 border-orange-200';
      case 'medium': return 'text-yellow-600 bg-yellow-100 border-yellow-200';
      case 'low': return 'text-blue-600 bg-blue-100 border-blue-200';
      case 'informational': return 'text-gray-600 bg-gray-100 border-gray-200';
      default: return 'text-gray-600 bg-gray-100 border-gray-200';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed': return <CheckCircleIcon className="h-5 w-5 text-green-600" />;
      case 'failed': return <XCircleIcon className="h-5 w-5 text-red-600" />;
      case 'analyzing': return <ClockIcon className="h-5 w-5 text-blue-600 animate-spin" />;
      case 'pending': return <ClockIcon className="h-5 w-5 text-yellow-600" />;
      default: return <ClockIcon className="h-5 w-5 text-gray-600" />;
    }
  };

  const formatFileSize = (bytes: number) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  return (
    <div className="enhanced-security-analysis p-6">
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 flex items-center">
            <ShieldCheckIcon className="h-8 w-8 mr-3 text-blue-600" />
            Enhanced Security Analysis
          </h1>
          <p className="text-gray-600 mt-1">AI-powered vulnerability detection and automated remediation</p>
        </div>
        
        <div className="flex space-x-3">
          <button
            onClick={loadDashboardData}
            className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors"
            disabled={loading}
          >
            <BoltIcon className="h-4 w-4 mr-2 inline" />
            Refresh
          </button>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex space-x-1 mb-6 bg-gray-100 p-1 rounded-lg">
        {[
          { id: 'dashboard', label: 'Dashboard', icon: ChartBarIcon },
          { id: 'upload', label: 'Upload & Analyze', icon: CloudArrowUpIcon },
          { id: 'reports', label: 'Analysis Reports', icon: DocumentTextIcon }
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as any)}
            className={`flex items-center px-4 py-2 rounded-md transition-colors ${
              activeTab === tab.id
                ? 'bg-white text-blue-600 shadow-sm'
                : 'text-gray-600 hover:text-gray-900'
            }`}
          >
            <tab.icon className="h-4 w-4 mr-2" />
            {tab.label}
          </button>
        ))}
      </div>

      {/* Dashboard Tab */}
      {activeTab === 'dashboard' && (
        <div className="space-y-6">
          {/* Metrics Cards */}
          {metrics && (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              <div className="bg-white p-6 rounded-lg shadow-sm border">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-600">Total Reports</p>
                    <p className="text-2xl font-bold text-gray-900">{metrics.total_reports}</p>
                    <p className="text-sm text-gray-500">{metrics.completed_reports} completed</p>
                  </div>
                  <DocumentTextIcon className="h-8 w-8 text-blue-600" />
                </div>
              </div>

              <div className="bg-white p-6 rounded-lg shadow-sm border">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-600">Success Rate</p>
                    <p className="text-2xl font-bold text-gray-900">{(metrics.success_rate * 100).toFixed(1)}%</p>
                    <p className="text-sm text-gray-500">{metrics.failed_reports} failed</p>
                  </div>
                  <CheckCircleIcon className="h-8 w-8 text-green-600" />
                </div>
              </div>

              <div className="bg-white p-6 rounded-lg shadow-sm border">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-600">Total Findings</p>
                    <p className="text-2xl font-bold text-gray-900">{metrics.total_findings}</p>
                    <p className="text-sm text-gray-500">Across all reports</p>
                  </div>
                  <ExclamationTriangleIcon className="h-8 w-8 text-orange-600" />
                </div>
              </div>

              <div className="bg-white p-6 rounded-lg shadow-sm border">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-600">Avg Analysis Time</p>
                    <p className="text-2xl font-bold text-gray-900">{metrics.average_execution_time.toFixed(1)}s</p>
                    <p className="text-sm text-gray-500">Per file</p>
                  </div>
                  <CpuChipIcon className="h-8 w-8 text-purple-600" />
                </div>
              </div>
            </div>
          )}

          {/* Severity Breakdown */}
          {metrics && (
            <div className="bg-white rounded-lg shadow-sm border">
              <div className="p-6 border-b">
                <h3 className="text-lg font-semibold text-gray-900">Vulnerability Severity Distribution</h3>
              </div>
              <div className="p-6">
                <div className="grid grid-cols-5 gap-4">
                  {Object.entries(metrics.severity_breakdown).map(([severity, count]) => (
                    <div key={severity} className="text-center">
                      <div className={`p-4 rounded-lg border-2 ${getSeverityColor(severity)}`}>
                        <div className="text-2xl font-bold">{count}</div>
                        <div className="text-sm font-medium capitalize">{severity}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* AI Models Status */}
          {metrics && (
            <div className="bg-white rounded-lg shadow-sm border">
              <div className="p-6 border-b">
                <h3 className="text-lg font-semibold text-gray-900">AI Models Status</h3>
              </div>
              <div className="p-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {Object.entries(metrics.ai_models_status).map(([model, accuracy]) => (
                    <div key={model} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                      <div>
                        <div className="font-medium text-gray-900">{model.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase())}</div>
                        <div className="text-sm text-gray-600">AI Detection Model</div>
                      </div>
                      <div className="text-right">
                        <div className="text-lg font-bold text-green-600">{(accuracy * 100).toFixed(1)}%</div>
                        <div className="text-xs text-gray-500">Accuracy</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Upload Tab */}
      {activeTab === 'upload' && (
        <div className="space-y-6">
          <div className="bg-white rounded-lg shadow-sm border">
            <div className="p-6 border-b">
              <h3 className="text-lg font-semibold text-gray-900">Upload Files for Security Analysis</h3>
              <p className="text-gray-600 mt-1">Upload source code, configuration files, or packages for comprehensive security analysis</p>
            </div>
            <div className="p-6">
              {/* File Upload Area */}
              <div className="border-2 border-dashed border-gray-300 rounded-lg p-8 text-center mb-6">
                <CloudArrowUpIcon className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                <div className="mb-4">
                  <label htmlFor="file-upload" className="cursor-pointer">
                    <span className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors">
                      Choose Files
                    </span>
                    <input
                      id="file-upload"
                      type="file"
                      multiple
                      className="hidden"
                      onChange={(e) => setSelectedFiles(e.target.files)}
                    />
                  </label>
                  <p className="text-gray-600 mt-2">or drag and drop files here</p>
                </div>
                <p className="text-sm text-gray-500">
                  Supports: Source code, configuration files, package manifests
                  <br />
                  Maximum: 100MB per file, 10 files total
                </p>
              </div>

              {/* Selected Files */}
              {selectedFiles && selectedFiles.length > 0 && (
                <div className="mb-6">
                  <h4 className="font-medium text-gray-900 mb-3">Selected Files ({selectedFiles.length})</h4>
                  <div className="space-y-2">
                    {Array.from(selectedFiles).map((file, index) => (
                      <div key={index} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                        <div className="flex items-center">
                          <DocumentTextIcon className="h-5 w-5 text-gray-400 mr-3" />
                          <div>
                            <div className="font-medium text-gray-900">{file.name}</div>
                            <div className="text-sm text-gray-600">{formatFileSize(file.size)}</div>
                          </div>
                        </div>
                        {uploadProgress[file.name] !== undefined && (
                          <div className="w-24">
                            <div className="bg-gray-200 rounded-full h-2">
                              <div
                                className="bg-blue-600 h-2 rounded-full transition-all"
                                style={{ width: `${uploadProgress[file.name]}%` }}
                              ></div>
                            </div>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Analysis Type Selection */}
              <div className="mb-6">
                <h4 className="font-medium text-gray-900 mb-3">Analysis Types</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {[
                    { id: 'static_analysis', name: 'Static Code Analysis', icon: MagnifyingGlassIcon },
                    { id: 'dependency_scan', name: 'Dependency Scan', icon: BeakerIcon },
                    { id: 'secret_detection', name: 'Secret Detection', icon: ShieldCheckIcon },
                    { id: 'malware_scan', name: 'Malware Scan', icon: ExclamationTriangleIcon },
                    { id: 'code_quality', name: 'Code Quality', icon: CheckCircleIcon },
                    { id: 'configuration_scan', name: 'Config Scan', icon: CpuChipIcon }
                  ].map((type) => (
                    <label key={type.id} className="flex items-center p-3 border rounded-lg cursor-pointer hover:bg-gray-50">
                      <input
                        type="checkbox"
                        checked={analysisTypes.includes(type.id)}
                        onChange={(e) => {
                          if (e.target.checked) {
                            setAnalysisTypes(prev => [...prev, type.id]);
                          } else {
                            setAnalysisTypes(prev => prev.filter(t => t !== type.id));
                          }
                        }}
                        className="mr-3"
                      />
                      <type.icon className="h-5 w-5 text-gray-400 mr-2" />
                      <span className="font-medium text-gray-900">{type.name}</span>
                    </label>
                  ))}
                </div>
              </div>

              {/* Upload Button */}
              <button
                onClick={handleFileUpload}
                disabled={!selectedFiles || selectedFiles.length === 0 || uploading}
                className="w-full bg-blue-600 text-white py-3 px-4 rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {uploading ? (
                  <>
                    <ClockIcon className="h-5 w-5 mr-2 inline animate-spin" />
                    Analyzing Files...
                  </>
                ) : (
                  <>
                    <CloudArrowUpIcon className="h-5 w-5 mr-2 inline" />
                    Start Security Analysis
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Reports Tab */}
      {activeTab === 'reports' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Reports List */}
          <div className="lg:col-span-1">
            <div className="bg-white rounded-lg shadow-sm border">
              <div className="p-6 border-b">
                <h3 className="text-lg font-semibold text-gray-900">Analysis Reports</h3>
              </div>
              <div className="divide-y divide-gray-200 max-h-96 overflow-y-auto">
                {reports.map((report) => (
                  <div
                    key={report.id}
                    onClick={() => handleReportSelect(report.id)}
                    className={`p-4 cursor-pointer hover:bg-gray-50 ${
                      selectedReport?.id === report.id ? 'bg-blue-50 border-r-4 border-blue-500' : ''
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center">
                        {getStatusIcon(report.status)}
                        <div className="ml-3">
                          <div className="font-medium text-gray-900 truncate">{report.filename}</div>
                          <div className="text-sm text-gray-600">
                            {report.findings_count} findings • {formatFileSize(report.file_size)}
                          </div>
                        </div>
                      </div>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          handleDeleteReport(report.id);
                        }}
                        className="text-red-600 hover:text-red-800"
                      >
                        <TrashIcon className="h-4 w-4" />
                      </button>
                    </div>
                    <div className="mt-2 flex space-x-1">
                      {Object.entries(report.severity_breakdown).map(([severity, count]) => (
                        count > 0 && (
                          <span
                            key={severity}
                            className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${getSeverityColor(severity)}`}
                          >
                            {count} {severity}
                          </span>
                        )
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Report Details */}
          <div className="lg:col-span-2">
            {selectedReport ? (
              <div className="space-y-6">
                {/* Report Summary */}
                <div className="bg-white rounded-lg shadow-sm border">
                  <div className="p-6 border-b">
                    <div className="flex items-center justify-between">
                      <h3 className="text-lg font-semibold text-gray-900">{selectedReport.filename}</h3>
                      <span className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium ${
                        selectedReport.status === 'completed' ? 'bg-green-100 text-green-800' : 
                        selectedReport.status === 'failed' ? 'bg-red-100 text-red-800' : 
                        'bg-yellow-100 text-yellow-800'
                      }`}>
                        {selectedReport.status.charAt(0).toUpperCase() + selectedReport.status.slice(1)}
                      </span>
                    </div>
                  </div>
                  <div className="p-6">
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                      <div>
                        <div className="text-sm font-medium text-gray-600">File Size</div>
                        <div className="text-lg font-semibold text-gray-900">{formatFileSize(selectedReport.file_size)}</div>
                      </div>
                      <div>
                        <div className="text-sm font-medium text-gray-600">Findings</div>
                        <div className="text-lg font-semibold text-gray-900">{selectedReport.findings_count}</div>
                      </div>
                      <div>
                        <div className="text-sm font-medium text-gray-600">Analysis Time</div>
                        <div className="text-lg font-semibold text-gray-900">
                          {selectedReport.execution_time ? `${selectedReport.execution_time.toFixed(1)}s` : '-'}
                        </div>
                      </div>
                      <div>
                        <div className="text-sm font-medium text-gray-600">Hash</div>
                        <div className="text-sm font-mono text-gray-900">{selectedReport.file_hash.slice(0, 8)}...</div>
                      </div>
                    </div>

                    {/* AI Summary */}
                    {selectedReport.ai_summary && (
                      <div className="mb-6">
                        <h4 className="font-medium text-gray-900 mb-2">AI Analysis Summary</h4>
                        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                          <pre className="text-sm text-blue-800 whitespace-pre-wrap font-sans">
                            {selectedReport.ai_summary}
                          </pre>
                        </div>
                      </div>
                    )}

                    {/* Remediation Suggestions */}
                    {selectedReport.remediation_suggestions.length > 0 && (
                      <div className="mb-6">
                        <h4 className="font-medium text-gray-900 mb-2">AI Remediation Suggestions</h4>
                        <div className="space-y-2">
                          {selectedReport.remediation_suggestions.map((suggestion, index) => (
                            <div key={index} className="flex items-start p-3 bg-green-50 border border-green-200 rounded-lg">
                              <CheckCircleIcon className="h-5 w-5 text-green-600 mr-2 mt-0.5 flex-shrink-0" />
                              <span className="text-sm text-green-800">{suggestion}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </div>

                {/* Findings */}
                <div className="bg-white rounded-lg shadow-sm border">
                  <div className="p-6 border-b">
                    <h3 className="text-lg font-semibold text-gray-900">Security Findings</h3>
                  </div>
                  <div className="divide-y divide-gray-200">
                    {selectedReport.findings.map((finding) => (
                      <div key={finding.id} className="p-6">
                        <div className="flex items-start justify-between">
                          <div className="flex-1">
                            <div className="flex items-center space-x-3 mb-2">
                              <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getSeverityColor(finding.severity)}`}>
                                {finding.severity.toUpperCase()}
                              </span>
                              <span className="text-sm text-gray-600">
                                Confidence: {(finding.confidence * 100).toFixed(0)}%
                              </span>
                              {finding.cvss_score && (
                                <span className="text-sm text-gray-600">
                                  CVSS: {finding.cvss_score}
                                </span>
                              )}
                            </div>
                            <h4 className="font-medium text-gray-900 mb-1">{finding.title}</h4>
                            <p className="text-gray-600 mb-3">{finding.description}</p>
                            
                            {finding.code_snippet && (
                              <div className="mb-3">
                                <div className="text-sm font-medium text-gray-700 mb-1">
                                  {finding.file_path}:{finding.line_number}
                                </div>
                                <pre className="bg-gray-100 p-2 rounded text-sm overflow-x-auto">
                                  <code>{finding.code_snippet}</code>
                                </pre>
                              </div>
                            )}
                            
                            {finding.remediation && (
                              <div className="mb-3">
                                <div className="text-sm font-medium text-gray-700 mb-1">Remediation:</div>
                                <p className="text-sm text-gray-600">{finding.remediation}</p>
                              </div>
                            )}
                          </div>
                          <div className="ml-4">
                            <button
                              onClick={() => toggleFalsePositive(selectedReport.id, finding.id, !finding.false_positive)}
                              className={`px-3 py-1 rounded text-sm font-medium ${
                                finding.false_positive
                                  ? 'bg-gray-100 text-gray-600 hover:bg-gray-200'
                                  : 'bg-orange-100 text-orange-600 hover:bg-orange-200'
                              }`}
                            >
                              {finding.false_positive ? 'Revert' : 'False Positive'}
                            </button>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            ) : (
              <div className="bg-white rounded-lg shadow-sm border">
                <div className="p-12 text-center">
                  <DocumentTextIcon className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                  <h3 className="text-lg font-medium text-gray-900 mb-2">Select a Report</h3>
                  <p className="text-gray-600">Choose an analysis report from the list to view details</p>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default EnhancedSecurityAnalysis;