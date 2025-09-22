'use client'

import { useState, useEffect } from 'react'
import ScanPanel from '../../../components/ScanPanel'
import { 
  ShieldCheckIcon, 
  BugAntIcon, 
  ClockIcon, 
  CheckCircleIcon,
  XCircleIcon,
  ChartBarIcon
} from '@heroicons/react/24/outline'

interface Scan {
  scan_id: number
  scan_name: string
  scan_type: string
  status: string
  created_at: string
  progress: number
}

export default function ScansPage() {
  const [scans, setScans] = useState<Scan[]>([])
  const [loading, setLoading] = useState(true)
  const [selectedScan, setSelectedScan] = useState<any>(null)

  useEffect(() => {
    fetchScans()
  }, [])

  const fetchScans = async () => {
    try {
      const token = localStorage.getItem('token')
      if (!token) {
        console.error('No authentication token found')
        return
      }

      const response = await fetch('http://localhost:8000/api/v1/scans/', {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      })
      
      if (response.ok) {
        const data = await response.json()
        setScans(data)
      } else {
        console.error('Failed to fetch scans:', response.status, response.statusText)
      }
    } catch (error) {
      console.error('Failed to fetch scans:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleScanComplete = (results: any) => {
    fetchScans() // Refresh the scans list
    setSelectedScan(results) // Show the results
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'COMPLETED':
        return <CheckCircleIcon className="w-5 h-5 text-green-400" />
      case 'FAILED':
        return <XCircleIcon className="w-5 h-5 text-red-400" />
      case 'RUNNING':
        return <ClockIcon className="w-5 h-5 text-yellow-400 animate-spin" />
      default:
        return <ClockIcon className="w-5 h-5 text-gray-400" />
    }
  }

  const getScanTypeIcon = (scanType: string) => {
    switch (scanType) {
      case 'SAST':
        return <BugAntIcon className="w-5 h-5 text-purple-400" />
      case 'DEPENDENCY':
      case 'SCA':
        return <ShieldCheckIcon className="w-5 h-5 text-blue-400" />
      default:
        return <ChartBarIcon className="w-5 h-5 text-gray-400" />
    }
  }

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    })
  }

  return (
    <div className="p-6 space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">Security Scans</h1>
          <p className="text-white/70">Analyze your code for vulnerabilities and security issues</p>
        </div>
        <div className="flex items-center space-x-4">
          <div className="bg-white/10 backdrop-blur-sm border border-white/20 rounded-lg px-4 py-2">
            <span className="text-white/70 text-sm">Total Scans: </span>
            <span className="text-white font-semibold">{scans.length}</span>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-8">
        {/* Scan Panel */}
        <div>
          <ScanPanel onScanComplete={handleScanComplete} />
        </div>

        {/* Recent Scans */}
        <div className="bg-white/10 backdrop-blur-xl border border-white/20 rounded-2xl p-6">
          <h2 className="text-xl font-semibold text-white mb-6 flex items-center">
            <ClockIcon className="w-6 h-6 text-purple-400 mr-3" />
            Recent Scans
          </h2>

          {loading ? (
            <div className="flex justify-center py-8">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-purple-400"></div>
            </div>
          ) : scans.length === 0 ? (
            <div className="text-center py-8">
              <BugAntIcon className="w-12 h-12 text-white/30 mx-auto mb-4" />
              <p className="text-white/60">No scans yet</p>
              <p className="text-white/40 text-sm">Start your first security scan</p>
            </div>
          ) : (
            <div className="space-y-4 max-h-96 overflow-y-auto">
              {scans.map((scan) => (
                <div
                  key={scan.scan_id}
                  className="p-4 bg-white/5 rounded-lg hover:bg-white/10 transition-colors cursor-pointer"
                  onClick={() => setSelectedScan(scan)}
                >
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center space-x-3">
                      {getScanTypeIcon(scan.scan_type)}
                      <div>
                        <h3 className="text-white font-medium text-sm">{scan.scan_name}</h3>
                        <p className="text-white/60 text-xs">{scan.scan_type}</p>
                      </div>
                    </div>
                    {getStatusIcon(scan.status)}
                  </div>
                  
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-white/50">{formatDate(scan.created_at)}</span>
                    <span className={`px-2 py-1 rounded font-medium ${
                      scan.status === 'COMPLETED' ? 'bg-green-500/20 text-green-300' :
                      scan.status === 'FAILED' ? 'bg-red-500/20 text-red-300' :
                      scan.status === 'RUNNING' ? 'bg-yellow-500/20 text-yellow-300' :
                      'bg-gray-500/20 text-gray-300'
                    }`}>
                      {scan.status}
                    </span>
                  </div>

                  {/* Progress bar for running scans */}
                  {scan.status === 'RUNNING' && (
                    <div className="mt-3">
                      <div className="bg-white/10 rounded-full h-2">
                        <div 
                          className="bg-gradient-to-r from-purple-500 to-pink-500 h-2 rounded-full transition-all duration-300"
                          style={{ width: `${scan.progress}%` }}
                        ></div>
                      </div>
                      <p className="text-white/60 text-xs mt-1">{scan.progress}% complete</p>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Scan Results Modal/Panel */}
      {selectedScan && (
        <div className="mt-8 bg-white/10 backdrop-blur-xl border border-white/20 rounded-2xl p-6">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-xl font-semibold text-white">
              Scan Results: {selectedScan.scan?.scan_name || selectedScan.scan_name}
            </h2>
            <button
              onClick={() => setSelectedScan(null)}
              className="text-white/60 hover:text-white transition-colors"
            >
              <XCircleIcon className="w-6 h-6" />
            </button>
          </div>

          {/* Results content would go here */}
          {selectedScan.findings && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                {Object.entries(selectedScan.summary || {}).map(([severity, count]) => (
                  <div key={severity} className="text-center p-4 bg-white/5 rounded-lg">
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

              <div className="space-y-3 max-h-64 overflow-y-auto">
                {selectedScan.findings.map((finding: any, index: number) => (
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
      )}
    </div>
  )
}
