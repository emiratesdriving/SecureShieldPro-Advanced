'use client'

import { useState } from 'react'
import { 
  CloudArrowUpIcon, 
  DocumentIcon, 
  XMarkIcon,
  ShieldCheckIcon,
  BugAntIcon,
  KeyIcon,
  CubeIcon
} from '@heroicons/react/24/outline'

interface ScanPanelProps {
  onScanComplete?: (results: any) => void
}

export default function ScanPanel({ onScanComplete }: ScanPanelProps) {
  const [files, setFiles] = useState<File[]>([])
  const [scanType, setScanType] = useState('SAST')
  const [scanName, setScanName] = useState('')
  const [isUploading, setIsUploading] = useState(false)
  const [isScanning, setIsScanning] = useState(false)
  const [scanResults, setScanResults] = useState<any>(null)
  const [error, setError] = useState('')

  const scanTypes = [
    { id: 'SAST', name: 'Static Analysis (SAST)', icon: BugAntIcon, description: 'Analyze source code for security vulnerabilities' },
    { id: 'DEPENDENCY', name: 'Dependency Scan', icon: CubeIcon, description: 'Check dependencies for known vulnerabilities' },
    { id: 'SECRETS', name: 'Secrets Detection', icon: KeyIcon, description: 'Detect hardcoded secrets and credentials' },
    { id: 'SCA', name: 'Software Composition', icon: ShieldCheckIcon, description: 'Analyze third-party components' }
  ]

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFiles = Array.from(event.target.files || [])
    setFiles(prev => [...prev, ...selectedFiles])
    setError('')
  }

  const removeFile = (index: number) => {
    setFiles(prev => prev.filter((_, i) => i !== index))
  }

  const handleDrop = (event: React.DragEvent) => {
    event.preventDefault()
    const droppedFiles = Array.from(event.dataTransfer.files)
    setFiles(prev => [...prev, ...droppedFiles])
  }

  const handleDragOver = (event: React.DragEvent) => {
    event.preventDefault()
  }

  const uploadFiles = async (): Promise<string[]> => {
    const uploadedFileIds: string[] = []
    
    for (const file of files) {
      const formData = new FormData()
      formData.append('file', file)
      
      const response = await fetch('http://localhost:8000/api/v1/scans/upload', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: formData
      })
      
      if (response.ok) {
        const result = await response.json()
        uploadedFileIds.push(result.file_id)
      } else {
        throw new Error(`Failed to upload ${file.name}`)
      }
    }
    
    return uploadedFileIds
  }

  const startScan = async () => {
    if (!scanName.trim()) {
      setError('Please enter a scan name')
      return
    }
    
    if (files.length === 0) {
      setError('Please select files to scan')
      return
    }

    setIsUploading(true)
    setError('')

    try {
      // Upload files first
      const fileIds = await uploadFiles()
      setIsUploading(false)
      setIsScanning(true)

      // Start scan for each uploaded file
      for (const fileId of fileIds) {
        const scanResponse = await fetch('http://localhost:8000/api/v1/scans/start', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${localStorage.getItem('token')}`
          },
          body: JSON.stringify({
            scan_name: scanName,
            scan_type: scanType,
            target: `/tmp/secureshield_scans/${fileId}`,
            options: {}
          })
        })

        if (scanResponse.ok) {
          const scanData = await scanResponse.json()
          
          // Poll for results
          const pollResults = async () => {
            const resultsResponse = await fetch(`http://localhost:8000/api/v1/scans/${scanData.scan_id}/results`, {
              headers: {
                'Authorization': `Bearer ${localStorage.getItem('token')}`
              }
            })
            
            if (resultsResponse.ok) {
              const results = await resultsResponse.json()
              if (results.scan.status === 'COMPLETED') {
                setScanResults(results)
                setIsScanning(false)
                onScanComplete?.(results)
                return
              } else if (results.scan.status === 'FAILED') {
                setError('Scan failed')
                setIsScanning(false)
                return
              }
              
              // Continue polling
              setTimeout(pollResults, 2000)
            }
          }
          
          // Start polling after a short delay
          setTimeout(pollResults, 1000)
        } else {
          throw new Error('Failed to start scan')
        }
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred')
      setIsUploading(false)
      setIsScanning(false)
    }
  }

  const formatFileSize = (bytes: number) => {
    if (bytes === 0) return '0 Bytes'
    const k = 1024
    const sizes = ['Bytes', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
  }

  const getFileIcon = (filename: string) => {
    const ext = filename.split('.').pop()?.toLowerCase()
    return <DocumentIcon className="w-5 h-5" />
  }

  return (
    <div className="bg-white/10 backdrop-blur-xl border border-white/20 rounded-2xl p-6">
      <div className="flex items-center mb-6">
        <ShieldCheckIcon className="w-6 h-6 text-purple-400 mr-3" />
        <h2 className="text-xl font-semibold text-white">Security Scanner</h2>
      </div>

      {/* Scan Configuration */}
      <div className="space-y-6">
        {/* Scan Name */}
        <div>
          <label className="block text-sm font-medium text-white/90 mb-2">
            Scan Name
          </label>
          <input
            type="text"
            value={scanName}
            onChange={(e) => setScanName(e.target.value)}
            className="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-white/50 focus:outline-none focus:ring-2 focus:ring-purple-500"
            placeholder="Enter scan name"
          />
        </div>

        {/* Scan Type Selection */}
        <div>
          <label className="block text-sm font-medium text-white/90 mb-3">
            Scan Type
          </label>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {scanTypes.map((type) => (
              <button
                key={type.id}
                onClick={() => setScanType(type.id)}
                className={`p-4 rounded-xl border-2 transition-all duration-200 text-left ${
                  scanType === type.id
                    ? 'border-purple-500 bg-purple-500/20'
                    : 'border-white/20 bg-white/5 hover:border-white/30'
                }`}
              >
                <div className="flex items-start space-x-3">
                  <type.icon className="w-5 h-5 text-purple-400 mt-1" />
                  <div>
                    <h3 className="text-white font-medium text-sm">{type.name}</h3>
                    <p className="text-white/60 text-xs mt-1">{type.description}</p>
                  </div>
                </div>
              </button>
            ))}
          </div>
        </div>

        {/* File Upload */}
        <div>
          <label className="block text-sm font-medium text-white/90 mb-3">
            Upload Files
          </label>
          
          {/* Drop Zone */}
          <div
            onDrop={handleDrop}
            onDragOver={handleDragOver}
            className="border-2 border-dashed border-white/30 rounded-xl p-8 text-center hover:border-purple-400 transition-colors"
          >
            <CloudArrowUpIcon className="w-12 h-12 text-white/50 mx-auto mb-4" />
            <p className="text-white/70 mb-2">Drag and drop files here, or</p>
            <label className="cursor-pointer">
              <span className="text-purple-400 hover:text-purple-300 font-medium">
                browse files
              </span>
              <input
                type="file"
                multiple
                onChange={handleFileUpload}
                className="hidden"
                accept=".py,.js,.ts,.jsx,.tsx,.java,.go,.php,.rb,.cs,.cpp,.c,.h,.json,.txt,.yml,.yaml,.xml,.html,.css,.scss,.vue,.svelte"
              />
            </label>
          </div>

          {/* File List */}
          {files.length > 0 && (
            <div className="mt-4 space-y-2">
              {files.map((file, index) => (
                <div key={index} className="flex items-center justify-between p-3 bg-white/5 rounded-lg">
                  <div className="flex items-center space-x-3">
                    {getFileIcon(file.name)}
                    <div>
                      <p className="text-white text-sm font-medium">{file.name}</p>
                      <p className="text-white/60 text-xs">{formatFileSize(file.size)}</p>
                    </div>
                  </div>
                  <button
                    onClick={() => removeFile(index)}
                    className="text-white/60 hover:text-red-400 transition-colors"
                  >
                    <XMarkIcon className="w-4 h-4" />
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Error Message */}
        {error && (
          <div className="p-4 bg-red-500/20 border border-red-500/30 rounded-lg">
            <p className="text-red-200 text-sm">{error}</p>
          </div>
        )}

        {/* Scan Button */}
        <button
          onClick={startScan}
          disabled={isUploading || isScanning || files.length === 0 || !scanName.trim()}
          className="w-full py-3 px-4 bg-gradient-to-r from-purple-500 to-pink-500 text-white font-semibold rounded-lg shadow-lg hover:from-purple-600 hover:to-pink-600 focus:outline-none focus:ring-2 focus:ring-purple-500 transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {isUploading ? (
            <div className="flex items-center justify-center">
              <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white mr-2"></div>
              Uploading files...
            </div>
          ) : isScanning ? (
            <div className="flex items-center justify-center">
              <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white mr-2"></div>
              Scanning in progress...
            </div>
          ) : (
            'Start Security Scan'
          )}
        </button>
      </div>

      {/* Scan Results */}
      {scanResults && (
        <div className="mt-8 p-6 bg-black/20 rounded-xl">
          <h3 className="text-lg font-semibold text-white mb-4">Scan Results</h3>
          
          {/* Summary */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
            {Object.entries(scanResults.summary).map(([severity, count]) => (
              <div key={severity} className="text-center">
                <div className={`text-2xl font-bold ${
                  severity === 'critical' ? 'text-red-400' :
                  severity === 'high' ? 'text-orange-400' :
                  severity === 'medium' ? 'text-yellow-400' :
                  severity === 'low' ? 'text-blue-400' : 'text-gray-400'
                }`}>
                  {String(count)}
                </div>
                <div className="text-white/60 text-sm capitalize">{severity}</div>
              </div>
            ))}
          </div>

          {/* Findings */}
          <div className="space-y-3 max-h-64 overflow-y-auto">
            {scanResults.findings.map((finding: any, index: number) => (
              <div key={index} className="p-4 bg-white/5 rounded-lg">
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <h4 className="text-white font-medium text-sm">{finding.title}</h4>
                    <p className="text-white/70 text-xs mt-1">{finding.description}</p>
                    {finding.file_path && (
                      <p className="text-white/50 text-xs mt-2">
                        {finding.file_path}:{finding.line_number}
                      </p>
                    )}
                  </div>
                  <span className={`px-2 py-1 rounded text-xs font-medium ${
                    finding.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-300' :
                    finding.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-300' :
                    finding.severity === 'MEDIUM' ? 'bg-yellow-500/20 text-yellow-300' :
                    finding.severity === 'LOW' ? 'bg-blue-500/20 text-blue-300' :
                    'bg-gray-500/20 text-gray-300'
                  }`}>
                    {finding.severity}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
