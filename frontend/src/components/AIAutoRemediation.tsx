import React, { useState, useEffect } from 'react';
import {
  ChartBarIcon,
  CpuChipIcon,
  ShieldCheckIcon,
  ExclamationTriangleIcon,
  PlayIcon,
  PauseIcon,
  ClockIcon,
  CheckCircleIcon,
  XCircleIcon,
  ArrowPathIcon,
  BoltIcon,
  SparklesIcon
} from '@heroicons/react/24/outline';

interface Vulnerability {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  cvssScore: number;
  autoRemediable: boolean;
  estimatedFixTime: number;
  status: 'open' | 'analyzing' | 'remediating' | 'fixed' | 'failed';
}

interface RemediationTask {
  id: string;
  vulnerabilityId: string;
  status: 'scheduled' | 'running' | 'completed' | 'failed';
  progress: number;
  estimatedTime: number;
  startTime?: Date;
}

const AIAutoRemediation: React.FC = () => {
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [remediationTasks, setRemediationTasks] = useState<RemediationTask[]>([]);
  const [selectedVulns, setSelectedVulns] = useState<string[]>([]);
  const [autoMode, setAutoMode] = useState(false);
  const [loading, setLoading] = useState(false);
  const [stats, setStats] = useState({
    totalRemediations: 0,
    successRate: 95,
    averageFixTime: '47 minutes',
    activeTasksCount: 0
  });

  // Mock data - in real app, fetch from API
  useEffect(() => {
    const mockVulns: Vulnerability[] = [
      {
        id: 'vuln-001',
        title: 'SQL Injection in User Authentication',
        severity: 'critical',
        description: 'SQL injection vulnerability in login endpoint allowing authentication bypass',
        cvssScore: 9.1,
        autoRemediable: true,
        estimatedFixTime: 45,
        status: 'open'
      },
      {
        id: 'vuln-002', 
        title: 'Cross-Site Scripting (XSS) in Comments',
        severity: 'high',
        description: 'Stored XSS vulnerability in user comment system',
        cvssScore: 7.8,
        autoRemediable: true,
        estimatedFixTime: 30,
        status: 'open'
      },
      {
        id: 'vuln-003',
        title: 'Weak SSL/TLS Configuration',
        severity: 'medium',
        description: 'Server accepts weak cipher suites and outdated TLS versions',
        cvssScore: 5.3,
        autoRemediable: true,
        estimatedFixTime: 15,
        status: 'open'
      },
      {
        id: 'vuln-004',
        title: 'Hardcoded API Credentials',
        severity: 'high',
        description: 'API keys and secrets hardcoded in source code',
        cvssScore: 8.2,
        autoRemediable: false,
        estimatedFixTime: 120,
        status: 'open'
      }
    ];
    setVulnerabilities(mockVulns);
  }, []);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-600 bg-red-100';
      case 'high': return 'text-orange-600 bg-orange-100';
      case 'medium': return 'text-yellow-600 bg-yellow-100';
      case 'low': return 'text-blue-600 bg-blue-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'open': return 'text-gray-600 bg-gray-100';
      case 'analyzing': return 'text-blue-600 bg-blue-100';
      case 'remediating': return 'text-yellow-600 bg-yellow-100';
      case 'fixed': return 'text-green-600 bg-green-100';
      case 'failed': return 'text-red-600 bg-red-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const analyzeVulnerability = async (vulnId: string) => {
    setLoading(true);
    try {
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      setVulnerabilities(prev => 
        prev.map(v => 
          v.id === vulnId 
            ? { ...v, status: 'analyzing' as const }
            : v
        )
      );

      // Simulate analysis completion
      setTimeout(() => {
        setVulnerabilities(prev => 
          prev.map(v => 
            v.id === vulnId 
              ? { ...v, status: 'open' as const }
              : v
          )
        );
      }, 3000);
    } catch (error) {
      console.error('Analysis failed:', error);
    } finally {
      setLoading(false);
    }
  };

  const startAutoRemediation = async (vulnId: string) => {
    setLoading(true);
    try {
      // Update vulnerability status
      setVulnerabilities(prev => 
        prev.map(v => 
          v.id === vulnId 
            ? { ...v, status: 'remediating' as const }
            : v
        )
      );

      // Create remediation task
      const task: RemediationTask = {
        id: `task-${Date.now()}`,
        vulnerabilityId: vulnId,
        status: 'running',
        progress: 0,
        estimatedTime: vulnerabilities.find(v => v.id === vulnId)?.estimatedFixTime || 30,
        startTime: new Date()
      };

      setRemediationTasks(prev => [...prev, task]);

      // Simulate progress
      const progressInterval = setInterval(() => {
        setRemediationTasks(prev => 
          prev.map(t => 
            t.id === task.id 
              ? { ...t, progress: Math.min(t.progress + 10, 100) }
              : t
          )
        );
      }, 1000);

      // Complete after estimated time
      setTimeout(() => {
        clearInterval(progressInterval);
        
        setRemediationTasks(prev => 
          prev.map(t => 
            t.id === task.id 
              ? { ...t, status: 'completed', progress: 100 }
              : t
          )
        );

        setVulnerabilities(prev => 
          prev.map(v => 
            v.id === vulnId 
              ? { ...v, status: 'fixed' as const }
              : v
          )
        );

        setStats(prev => ({
          ...prev,
          totalRemediations: prev.totalRemediations + 1
        }));
      }, task.estimatedTime * 100); // Accelerated for demo

    } catch (error) {
      console.error('Remediation failed:', error);
      setVulnerabilities(prev => 
        prev.map(v => 
          v.id === vulnId 
            ? { ...v, status: 'failed' as const }
            : v
        )
      );
    } finally {
      setLoading(false);
    }
  };

  const batchRemediate = async () => {
    const autoRemediableSelected = selectedVulns.filter(id => 
      vulnerabilities.find(v => v.id === id)?.autoRemediable
    );

    for (const vulnId of autoRemediableSelected) {
      await startAutoRemediation(vulnId);
      // Small delay between remediations
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
  };

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 flex items-center gap-3">
            <SparklesIcon className="h-8 w-8 text-purple-600" />
            AI Auto-Remediation Engine
          </h1>
          <p className="text-gray-600 mt-2">
            Automatically fix vulnerabilities with AI-powered remediation
          </p>
        </div>
        
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <span className="text-sm text-gray-600">Auto Mode:</span>
            <button
              onClick={() => setAutoMode(!autoMode)}
              className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                autoMode ? 'bg-purple-600' : 'bg-gray-200'
              }`}
            >
              <span
                className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                  autoMode ? 'translate-x-6' : 'translate-x-1'
                }`}
              />
            </button>
          </div>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="bg-white rounded-lg p-6 shadow-sm border border-gray-200">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600">Total Remediations</p>
              <p className="text-2xl font-bold text-gray-900">{stats.totalRemediations}</p>
            </div>
            <ChartBarIcon className="h-8 w-8 text-blue-600" />
          </div>
        </div>

        <div className="bg-white rounded-lg p-6 shadow-sm border border-gray-200">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600">Success Rate</p>
              <p className="text-2xl font-bold text-green-600">{stats.successRate}%</p>
            </div>
            <CheckCircleIcon className="h-8 w-8 text-green-600" />
          </div>
        </div>

        <div className="bg-white rounded-lg p-6 shadow-sm border border-gray-200">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600">Avg Fix Time</p>
              <p className="text-2xl font-bold text-purple-600">{stats.averageFixTime}</p>
            </div>
            <ClockIcon className="h-8 w-8 text-purple-600" />
          </div>
        </div>

        <div className="bg-white rounded-lg p-6 shadow-sm border border-gray-200">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600">Active Tasks</p>
              <p className="text-2xl font-bold text-orange-600">{remediationTasks.filter(t => t.status === 'running').length}</p>
            </div>
            <CpuChipIcon className="h-8 w-8 text-orange-600" />
          </div>
        </div>
      </div>

      {/* Active Remediation Tasks */}
      {remediationTasks.filter(t => t.status === 'running').length > 0 && (
        <div className="bg-white rounded-lg p-6 shadow-sm border border-gray-200">
          <h2 className="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
            <ArrowPathIcon className="h-5 w-5 text-blue-600 animate-spin" />
            Active Remediation Tasks
          </h2>
          <div className="space-y-4">
            {remediationTasks.filter(t => t.status === 'running').map(task => {
              const vuln = vulnerabilities.find(v => v.id === task.vulnerabilityId);
              return (
                <div key={task.id} className="border border-gray-200 rounded-lg p-4">
                  <div className="flex items-center justify-between mb-2">
                    <h3 className="font-medium text-gray-900">{vuln?.title}</h3>
                    <span className="text-sm text-gray-600">{task.progress}%</span>
                  </div>
                  <div className="w-full bg-gray-200 rounded-full h-2 mb-2">
                    <div 
                      className="bg-blue-600 h-2 rounded-full transition-all duration-500"
                      style={{ width: `${task.progress}%` }}
                    />
                  </div>
                  <div className="flex items-center justify-between text-sm text-gray-600">
                    <span>Est. Time: {task.estimatedTime} minutes</span>
                    <span>Started: {task.startTime?.toLocaleTimeString()}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Vulnerabilities List */}
      <div className="bg-white rounded-lg p-6 shadow-sm border border-gray-200">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-lg font-semibold text-gray-900 flex items-center gap-2">
            <ExclamationTriangleIcon className="h-5 w-5 text-orange-600" />
            Vulnerabilities
          </h2>
          
          <div className="flex items-center gap-3">
            {selectedVulns.length > 0 && (
              <button
                onClick={batchRemediate}
                disabled={loading}
                className="bg-purple-600 text-white px-4 py-2 rounded-lg hover:bg-purple-700 disabled:opacity-50 flex items-center gap-2"
              >
                <BoltIcon className="h-4 w-4" />
                Batch Remediate ({selectedVulns.length})
              </button>
            )}
            
            <button
              onClick={() => setSelectedVulns([])}
              className="text-gray-600 hover:text-gray-800"
            >
              Clear Selection
            </button>
          </div>
        </div>

        <div className="space-y-4">
          {vulnerabilities.map(vuln => (
            <div key={vuln.id} className="border border-gray-200 rounded-lg p-4 hover:border-gray-300 transition-colors">
              <div className="flex items-start justify-between">
                <div className="flex items-start gap-3">
                  <input
                    type="checkbox"
                    checked={selectedVulns.includes(vuln.id)}
                    onChange={(e) => {
                      if (e.target.checked) {
                        setSelectedVulns(prev => [...prev, vuln.id]);
                      } else {
                        setSelectedVulns(prev => prev.filter(id => id !== vuln.id));
                      }
                    }}
                    className="mt-1 h-4 w-4 text-purple-600 rounded border-gray-300 focus:ring-purple-500"
                  />
                  
                  <div className="flex-1">
                    <div className="flex items-center gap-3 mb-2">
                      <h3 className="font-medium text-gray-900">{vuln.title}</h3>
                      
                      <span className={`px-2 py-1 rounded-full text-xs font-medium ${getSeverityColor(vuln.severity)}`}>
                        {vuln.severity.toUpperCase()}
                      </span>
                      
                      <span className={`px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(vuln.status)}`}>
                        {vuln.status.toUpperCase()}
                      </span>
                      
                      {vuln.autoRemediable && (
                        <span className="px-2 py-1 rounded-full text-xs font-medium text-green-600 bg-green-100 flex items-center gap-1">
                          <BoltIcon className="h-3 w-3" />
                          Auto-Remediable
                        </span>
                      )}
                    </div>
                    
                    <p className="text-gray-600 text-sm mb-2">{vuln.description}</p>
                    
                    <div className="flex items-center gap-4 text-sm text-gray-500">
                      <span>CVSS: {vuln.cvssScore}</span>
                      <span>Est. Fix Time: {vuln.estimatedFixTime} min</span>
                    </div>
                  </div>
                </div>
                
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => analyzeVulnerability(vuln.id)}
                    disabled={loading || vuln.status === 'analyzing'}
                    className="bg-blue-600 text-white px-3 py-1 rounded text-sm hover:bg-blue-700 disabled:opacity-50 flex items-center gap-1"
                  >
                    <CpuChipIcon className="h-4 w-4" />
                    Analyze
                  </button>
                  
                  {vuln.autoRemediable && vuln.status === 'open' && (
                    <button
                      onClick={() => startAutoRemediation(vuln.id)}
                      disabled={loading}
                      className="bg-green-600 text-white px-3 py-1 rounded text-sm hover:bg-green-700 disabled:opacity-50 flex items-center gap-1"
                    >
                      <PlayIcon className="h-4 w-4" />
                      Auto-Fix
                    </button>
                  )}
                  
                  {vuln.status === 'fixed' && (
                    <span className="text-green-600 flex items-center gap-1 text-sm">
                      <CheckCircleIcon className="h-4 w-4" />
                      Fixed
                    </span>
                  )}
                  
                  {vuln.status === 'failed' && (
                    <span className="text-red-600 flex items-center gap-1 text-sm">
                      <XCircleIcon className="h-4 w-4" />
                      Failed
                    </span>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default AIAutoRemediation;