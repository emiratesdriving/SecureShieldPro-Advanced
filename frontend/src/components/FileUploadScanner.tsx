'use client';

import { useState, useRef } from 'react';
import { 
  CloudArrowUpIcon, 
  DocumentIcon, 
  XMarkIcon,
  CheckCircleIcon,
  ExclamationTriangleIcon
} from '@heroicons/react/24/outline';

interface FileUploadProps {
  onFileUploaded?: (file: File, scanResult: any) => void;
}

interface UploadedFile {
  file: File;
  id: string;
  status: 'uploading' | 'scanning' | 'completed' | 'error';
  progress: number;
  scanResult?: any;
  error?: string;
}

export default function FileUploadScanner({ onFileUploaded }: FileUploadProps) {
  const [uploadedFiles, setUploadedFiles] = useState<UploadedFile[]>([]);
  const [isDragOver, setIsDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileSelect = (files: FileList) => {
    const newFiles = Array.from(files).map(file => ({
      file,
      id: Math.random().toString(36).substr(2, 9),
      status: 'uploading' as const,
      progress: 0
    }));

    setUploadedFiles(prev => [...prev, ...newFiles]);

    // Process each file
    newFiles.forEach(uploadedFile => {
      simulateFileUploadAndScan(uploadedFile);
    });
  };

  const simulateFileUploadAndScan = async (uploadedFile: UploadedFile) => {
    try {
      // Simulate upload progress
      for (let progress = 0; progress <= 100; progress += 10) {
        await new Promise(resolve => setTimeout(resolve, 100));
        setUploadedFiles(prev => 
          prev.map(f => 
            f.id === uploadedFile.id 
              ? { ...f, progress }
              : f
          )
        );
      }

      // Change to scanning status
      setUploadedFiles(prev => 
        prev.map(f => 
          f.id === uploadedFile.id 
            ? { ...f, status: 'scanning', progress: 0 }
            : f
        )
      );

      // Simulate scanning progress
      for (let progress = 0; progress <= 100; progress += 20) {
        await new Promise(resolve => setTimeout(resolve, 500));
        setUploadedFiles(prev => 
          prev.map(f => 
            f.id === uploadedFile.id 
              ? { ...f, progress }
              : f
          )
        );
      }

      // Generate mock scan results
      const mockScanResult = {
        threatLevel: Math.random() > 0.7 ? 'high' : Math.random() > 0.4 ? 'medium' : 'low',
        vulnerabilities: Math.floor(Math.random() * 5),
        score: Math.floor(Math.random() * 100),
        findings: [
          'SQL injection vulnerability detected',
          'Cross-site scripting (XSS) risk',
          'Insecure dependencies found'
        ].slice(0, Math.floor(Math.random() * 3) + 1)
      };

      // Complete scan
      setUploadedFiles(prev => 
        prev.map(f => 
          f.id === uploadedFile.id 
            ? { ...f, status: 'completed', progress: 100, scanResult: mockScanResult }
            : f
        )
      );

      if (onFileUploaded) {
        onFileUploaded(uploadedFile.file, mockScanResult);
      }
    } catch (error) {
      setUploadedFiles(prev => 
        prev.map(f => 
          f.id === uploadedFile.id 
            ? { ...f, status: 'error', error: 'Scan failed' }
            : f
        )
      );
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
    if (e.dataTransfer.files) {
      handleFileSelect(e.dataTransfer.files);
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
  };

  const removeFile = (id: string) => {
    setUploadedFiles(prev => prev.filter(f => f.id !== id));
  };

  const getSeverityColor = (level: string) => {
    switch (level) {
      case 'high': return 'text-red-400 bg-red-500/20';
      case 'medium': return 'text-yellow-400 bg-yellow-500/20';
      case 'low': return 'text-green-400 bg-green-500/20';
      default: return 'text-gray-400 bg-gray-500/20';
    }
  };

  return (
    <div className="space-y-4">
      {/* Upload Area */}
      <div
        className={`border-2 border-dashed rounded-xl p-8 text-center transition-all duration-200 ${
          isDragOver
            ? 'border-blue-400 bg-blue-500/10'
            : 'border-white/30 hover:border-white/50 bg-white/5 hover:bg-white/10'
        }`}
        onDrop={handleDrop}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onClick={() => fileInputRef.current?.click()}
      >
        <CloudArrowUpIcon className="mx-auto h-12 w-12 text-gray-400 mb-4" />
        <h3 className="text-lg font-medium text-white mb-2">Upload Files for Security Scan</h3>
        <p className="text-gray-400 mb-4">
          Drag and drop files here, or click to select files
        </p>
        <p className="text-sm text-gray-500">
          Supports: .js, .ts, .py, .java, .php, .rb, .go, .cs, .cpp, .c, .zip
        </p>
        <input
          ref={fileInputRef}
          type="file"
          multiple
          className="hidden"
          accept=".js,.ts,.py,.java,.php,.rb,.go,.cs,.cpp,.c,.zip,.tar,.gz"
          onChange={(e) => e.target.files && handleFileSelect(e.target.files)}
        />
      </div>

      {/* Uploaded Files */}
      {uploadedFiles.length > 0 && (
        <div className="space-y-3">
          <h4 className="text-sm font-medium text-gray-300">Uploaded Files</h4>
          {uploadedFiles.map((uploadedFile) => (
            <div
              key={uploadedFile.id}
              className="bg-white/10 rounded-lg p-4 border border-white/20"
            >
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center space-x-3">
                  <DocumentIcon className="h-5 w-5 text-blue-400" />
                  <span className="text-white font-medium">{uploadedFile.file.name}</span>
                  <span className="text-gray-400 text-sm">
                    ({(uploadedFile.file.size / 1024).toFixed(1)} KB)
                  </span>
                </div>
                <button
                  onClick={() => removeFile(uploadedFile.id)}
                  className="text-gray-400 hover:text-white"
                >
                  <XMarkIcon className="h-4 w-4" />
                </button>
              </div>

              {/* Progress Bar */}
              {(uploadedFile.status === 'uploading' || uploadedFile.status === 'scanning') && (
                <div className="mb-3">
                  <div className="flex justify-between text-sm mb-1">
                    <span className="text-gray-300">
                      {uploadedFile.status === 'uploading' ? 'Uploading...' : 'Scanning...'}
                    </span>
                    <span className="text-gray-300">{uploadedFile.progress}%</span>
                  </div>
                  <div className="w-full bg-gray-700 rounded-full h-2">
                    <div
                      className="bg-blue-500 h-2 rounded-full transition-all duration-300"
                      style={{ width: `${uploadedFile.progress}%` }}
                    ></div>
                  </div>
                </div>
              )}

              {/* Status */}
              <div className="flex items-center space-x-2">
                {uploadedFile.status === 'completed' && (
                  <>
                    <CheckCircleIcon className="h-4 w-4 text-green-400" />
                    <span className="text-green-400 text-sm">Scan completed</span>
                  </>
                )}
                {uploadedFile.status === 'error' && (
                  <>
                    <ExclamationTriangleIcon className="h-4 w-4 text-red-400" />
                    <span className="text-red-400 text-sm">{uploadedFile.error}</span>
                  </>
                )}
              </div>

              {/* Scan Results */}
              {uploadedFile.scanResult && (
                <div className="mt-3 p-3 bg-white/5 rounded-lg border border-white/10">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-white font-medium">Scan Results</span>
                    <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(uploadedFile.scanResult.threatLevel)}`}>
                      {uploadedFile.scanResult.threatLevel.toUpperCase()} RISK
                    </span>
                  </div>
                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div>
                      <span className="text-gray-400">Security Score:</span>
                      <span className="text-white ml-2">{uploadedFile.scanResult.score}/100</span>
                    </div>
                    <div>
                      <span className="text-gray-400">Vulnerabilities:</span>
                      <span className="text-white ml-2">{uploadedFile.scanResult.vulnerabilities}</span>
                    </div>
                  </div>
                  {uploadedFile.scanResult.findings.length > 0 && (
                    <div className="mt-2">
                      <span className="text-gray-400 text-xs">Key Findings:</span>
                      <ul className="text-xs text-gray-300 mt-1 space-y-1">
                        {uploadedFile.scanResult.findings.map((finding: string, index: number) => (
                          <li key={index} className="flex items-center">
                            <div className="w-1 h-1 bg-yellow-400 rounded-full mr-2"></div>
                            {finding}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}