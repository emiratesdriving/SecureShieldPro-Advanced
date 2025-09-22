'use client';

import React, { useState, useEffect } from 'react';
import {
  CogIcon,
  PlayIcon,
  PauseIcon,
  StopIcon,
  CheckCircleIcon,
  XCircleIcon,
  ClockIcon,
  ExclamationTriangleIcon,
  DocumentTextIcon,
  BoltIcon,
  ArrowPathIcon,
  PlusIcon,
  EyeIcon,
  FireIcon,
  BeakerIcon
} from '@heroicons/react/24/outline';

interface Incident {
  incident_id: string;
  title: string;
  severity: string;
  status: string;
  created_at: string;
  affected_assets: string[];
  playbooks_executed: string[];
  timeline_entries: number;
}

interface Execution {
  execution_id: string;
  playbook_id: string;
  incident_id: string;
  status: string;
  started_at: string;
  completed_at?: string;
  success_rate: number;
  current_step?: string;
  log_entries: number;
}

interface SOARSummary {
  incidents: {
    total_incidents: number;
    by_severity: Record<string, number>;
    by_status: Record<string, number>;
    recent_incidents: any[];
  };
  executions: {
    total_recent: number;
    success_rate: number;
    running: number;
  };
  playbooks: {
    total: number;
    active: number;
  };
}

export default function SOARPage() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [executions, setExecutions] = useState<Execution[]>([]);
  const [summary, setSummary] = useState<SOARSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'incidents' | 'executions'>('incidents');

  const fetchIncidents = async () => {
    try {
      const response = await fetch('/api/v1/soar/incidents?limit=50');
      if (response.ok) {
        const data = await response.json();
        setIncidents(data.incidents || []);
      }
    } catch (err) {
      setError('Failed to fetch incidents');
    }
  };

  const fetchExecutions = async () => {
    try {
      const response = await fetch('/api/v1/soar/executions?limit=50');
      if (response.ok) {
        const data = await response.json();
        setExecutions(data.executions || []);
      }
    } catch (err) {
      setError('Failed to fetch executions');
    }
  };

  const fetchSummary = async () => {
    try {
      const response = await fetch('/api/v1/soar/summary');
      if (response.ok) {
        const data = await response.json();
        setSummary(data);
      }
    } catch (err) {
      setError('Failed to fetch summary');
    }
  };

  const simulateIncident = async (incidentType: string) => {
    try {
      const response = await fetch('/api/v1/soar/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          incident_type: incidentType,
          severity: 'high'
        })
      });
      
      if (response.ok) {
        await Promise.all([fetchIncidents(), fetchExecutions(), fetchSummary()]);
      }
    } catch (err) {
      console.error('Failed to simulate incident:', err);
    }
  };

  useEffect(() => {
    const loadData = async () => {
      await Promise.all([fetchIncidents(), fetchExecutions(), fetchSummary()]);
      setLoading(false);
    };
    loadData();
  }, []);

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'text-red-500 bg-red-500/10 border-red-500/20';
      case 'high': return 'text-orange-500 bg-orange-500/10 border-orange-500/20';
      case 'medium': return 'text-yellow-500 bg-yellow-500/10 border-yellow-500/20';
      case 'low': return 'text-blue-500 bg-blue-500/10 border-blue-500/20';
      default: return 'text-gray-500 bg-gray-500/10 border-gray-500/20';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'open': return 'text-red-400 bg-red-400/10';
      case 'investigating': return 'text-yellow-400 bg-yellow-400/10';
      case 'contained': return 'text-blue-400 bg-blue-400/10';
      case 'resolved': return 'text-green-400 bg-green-400/10';
      case 'running': return 'text-blue-400 bg-blue-400/10';
      case 'completed': return 'text-green-400 bg-green-400/10';
      case 'failed': return 'text-red-400 bg-red-400/10';
      default: return 'text-gray-400 bg-gray-400/10';
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-indigo-900 p-6">
        <div className="animate-pulse space-y-6">
          <div className="h-8 bg-white/10 rounded-lg w-1/3"></div>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
            {[...Array(4)].map((_, i) => (
              <div key={i} className="h-24 bg-white/10 rounded-lg"></div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-indigo-900 p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-3xl font-bold text-white flex items-center gap-3">
                <CogIcon className="h-8 w-8 text-blue-400" />
                SOAR Platform
              </h1>
              <p className="text-gray-300 mt-2">
                Security Orchestration, Automation & Response
              </p>
            </div>
            <div className="flex gap-3">
              <button
                onClick={() => simulateIncident('malware_detection')}
                className="bg-orange-600 hover:bg-orange-700 text-white px-4 py-2 rounded-lg transition-colors flex items-center gap-2"
              >
                <BeakerIcon className="h-5 w-5" />
                Simulate Malware
              </button>
              <button
                onClick={() => simulateIncident('data_breach')}
                className="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg transition-colors flex items-center gap-2"
              >
                <FireIcon className="h-5 w-5" />
                Simulate Breach
              </button>
            </div>
          </div>
        </div>

        {/* Summary Cards */}
        {summary && (
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
            <div className="bg-white/10 backdrop-blur-sm rounded-lg p-6 border border-white/20">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-300">Total Incidents</p>
                  <p className="text-2xl font-bold text-white">{summary.incidents.total_incidents}</p>
                </div>
                <ExclamationTriangleIcon className="h-8 w-8 text-orange-400" />
              </div>
            </div>

            <div className="bg-white/10 backdrop-blur-sm rounded-lg p-6 border border-white/20">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-300">Success Rate</p>
                  <p className="text-2xl font-bold text-white">{(summary.executions.success_rate * 100).toFixed(1)}%</p>
                </div>
                <CheckCircleIcon className="h-8 w-8 text-green-400" />
              </div>
            </div>

            <div className="bg-white/10 backdrop-blur-sm rounded-lg p-6 border border-white/20">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-300">Running Executions</p>
                  <p className="text-2xl font-bold text-blue-400">{summary.executions.running}</p>
                </div>
                <PlayIcon className="h-8 w-8 text-blue-400" />
              </div>
            </div>

            <div className="bg-white/10 backdrop-blur-sm rounded-lg p-6 border border-white/20">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-300">Active Playbooks</p>
                  <p className="text-2xl font-bold text-green-400">{summary.playbooks.active}</p>
                </div>
                <DocumentTextIcon className="h-8 w-8 text-green-400" />
              </div>
            </div>
          </div>
        )}

        {/* Tabs */}
        <div className="bg-white/10 backdrop-blur-sm rounded-lg border border-white/20">
          <div className="border-b border-white/20">
            <nav className="flex space-x-8 px-6">
              <button
                onClick={() => setActiveTab('incidents')}
                className={`py-4 px-1 border-b-2 font-medium text-sm ${
                  activeTab === 'incidents'
                    ? 'border-blue-400 text-blue-400'
                    : 'border-transparent text-gray-300 hover:text-white hover:border-gray-300'
                }`}
              >
                Security Incidents
              </button>
              <button
                onClick={() => setActiveTab('executions')}
                className={`py-4 px-1 border-b-2 font-medium text-sm ${
                  activeTab === 'executions'
                    ? 'border-blue-400 text-blue-400'
                    : 'border-transparent text-gray-300 hover:text-white hover:border-gray-300'
                }`}
              >
                Playbook Executions
              </button>
            </nav>
          </div>

          {/* Incidents Tab */}
          {activeTab === 'incidents' && (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-white/5">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                      Incident
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                      Severity
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                      Status
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                      Assets
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                      Playbooks
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                      Created
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/10">
                  {incidents.map((incident) => (
                    <tr key={incident.incident_id} className="hover:bg-white/5 transition-colors">
                      <td className="px-6 py-4">
                        <div>
                          <p className="text-sm font-medium text-white">{incident.title}</p>
                          <p className="text-xs text-gray-400">ID: {incident.incident_id.slice(0, 8)}</p>
                        </div>
                      </td>
                      <td className="px-6 py-4">
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border ${getSeverityColor(incident.severity)}`}>
                          {incident.severity.toUpperCase()}
                        </span>
                      </td>
                      <td className="px-6 py-4">
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(incident.status)}`}>
                          {incident.status.toUpperCase()}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-300">
                        {incident.affected_assets.length} asset(s)
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-300">
                        {incident.playbooks_executed.length} executed
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-300">
                        <div className="flex items-center gap-1">
                          <ClockIcon className="h-4 w-4" />
                          {new Date(incident.created_at).toLocaleTimeString()}
                        </div>
                        <div className="text-xs text-gray-400">
                          {new Date(incident.created_at).toLocaleDateString()}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>

              {incidents.length === 0 && (
                <div className="text-center py-12">
                  <ExclamationTriangleIcon className="mx-auto h-12 w-12 text-gray-400" />
                  <h3 className="mt-2 text-sm font-medium text-gray-300">No security incidents</h3>
                  <p className="mt-1 text-sm text-gray-400">Simulate an incident to see SOAR automation in action.</p>
                </div>
              )}
            </div>
          )}

          {/* Executions Tab */}
          {activeTab === 'executions' && (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-white/5">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                      Execution
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                      Status
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                      Success Rate
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                      Current Step
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                      Duration
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                      Logs
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/10">
                  {executions.map((execution) => (
                    <tr key={execution.execution_id} className="hover:bg-white/5 transition-colors">
                      <td className="px-6 py-4">
                        <div>
                          <p className="text-sm font-medium text-white">
                            Playbook: {execution.playbook_id}
                          </p>
                          <p className="text-xs text-gray-400">ID: {execution.execution_id.slice(0, 8)}</p>
                        </div>
                      </td>
                      <td className="px-6 py-4">
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(execution.status)}`}>
                          {execution.status.toUpperCase()}
                        </span>
                      </td>
                      <td className="px-6 py-4">
                        <div className="flex items-center">
                          <div className="flex-1 bg-gray-700 rounded-full h-2 mr-3">
                            <div 
                              className="bg-green-400 h-2 rounded-full" 
                              style={{ width: `${execution.success_rate * 100}%` }}
                            ></div>
                          </div>
                          <span className="text-sm text-white">{(execution.success_rate * 100).toFixed(0)}%</span>
                        </div>
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-300">
                        {execution.current_step || 'N/A'}
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-300">
                        {execution.completed_at ? (
                          `${Math.round((new Date(execution.completed_at).getTime() - new Date(execution.started_at).getTime()) / 1000)}s`
                        ) : (
                          'Running...'
                        )}
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-300">
                        {execution.log_entries} entries
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>

              {executions.length === 0 && (
                <div className="text-center py-12">
                  <PlayIcon className="mx-auto h-12 w-12 text-gray-400" />
                  <h3 className="mt-2 text-sm font-medium text-gray-300">No playbook executions</h3>
                  <p className="mt-1 text-sm text-gray-400">Create an incident to trigger automated playbook execution.</p>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}