'use client';

import React, { useState, useEffect } from 'react';
import {
  ShieldExclamationIcon,
  CpuChipIcon,
  ChartBarIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  ClockIcon,
  EyeIcon,
  PlayIcon,
  FireIcon,
  BoltIcon,
  BeakerIcon
} from '@heroicons/react/24/outline';

interface ThreatEvent {
  event_id: string;
  timestamp: string;
  source_ip: string;
  target: string;
  category: string;
  level: string;
  confidence: number;
  description: string;
  mitigation: string[];
  indicators_count: number;
}

interface ThreatSummary {
  total_threats: number;
  threats_by_category: Record<string, number>;
  threats_by_level: Record<string, number>;
  avg_confidence: number;
  latest_threats: any[];
}

export default function ThreatDetectionPage() {
  const [threats, setThreats] = useState<ThreatEvent[]>([]);
  const [summary, setSummary] = useState<ThreatSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedThreat, setSelectedThreat] = useState<ThreatEvent | null>(null);

  const fetchThreats = async () => {
    try {
      setLoading(true);
      const response = await fetch('/api/v1/threat-detection/events?limit=50');
      if (response.ok) {
        const data = await response.json();
        setThreats(data);
      }
    } catch (err) {
      setError('Failed to fetch threat events');
    }
  };

  const fetchSummary = async () => {
    try {
      const response = await fetch('/api/v1/threat-detection/summary');
      if (response.ok) {
        const data = await response.json();
        setSummary(data);
      }
    } catch (err) {
      setError('Failed to fetch threat summary');
    }
  };

  const simulateThreat = async (threatType: string) => {
    try {
      const response = await fetch('/api/v1/threat-detection/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ threat_type: threatType })
      });
      
      if (response.ok) {
        await fetchThreats();
        await fetchSummary();
      }
    } catch (err) {
      console.error('Failed to simulate threat:', err);
    }
  };

  useEffect(() => {
    const loadData = async () => {
      await Promise.all([fetchThreats(), fetchSummary()]);
      setLoading(false);
    };
    loadData();
  }, []);

  const getLevelColor = (level: string) => {
    switch (level.toLowerCase()) {
      case 'critical': return 'text-red-500 bg-red-500/10 border-red-500/20';
      case 'high': return 'text-orange-500 bg-orange-500/10 border-orange-500/20';
      case 'medium': return 'text-yellow-500 bg-yellow-500/10 border-yellow-500/20';
      case 'low': return 'text-blue-500 bg-blue-500/10 border-blue-500/20';
      default: return 'text-gray-500 bg-gray-500/10 border-gray-500/20';
    }
  };

  const getCategoryIcon = (category: string) => {
    switch (category.toLowerCase()) {
      case 'malware': return <FireIcon className="h-5 w-5" />;
      case 'network': return <BoltIcon className="h-5 w-5" />;
      case 'intrusion': return <ExclamationTriangleIcon className="h-5 w-5" />;
      default: return <ShieldExclamationIcon className="h-5 w-5" />;
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
                <CpuChipIcon className="h-8 w-8 text-blue-400" />
                Advanced Threat Detection
              </h1>
              <p className="text-gray-300 mt-2">
                ML-powered threat analysis with behavioral detection
              </p>
            </div>
            <div className="flex gap-3">
              <button
                onClick={() => simulateThreat('sql_injection')}
                className="bg-orange-600 hover:bg-orange-700 text-white px-4 py-2 rounded-lg transition-colors flex items-center gap-2"
              >
                <BeakerIcon className="h-5 w-5" />
                Simulate SQL Injection
              </button>
              <button
                onClick={() => simulateThreat('malicious_ip')}
                className="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg transition-colors flex items-center gap-2"
              >
                <FireIcon className="h-5 w-5" />
                Simulate Malicious IP
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
                  <p className="text-sm text-gray-300">Total Threats</p>
                  <p className="text-2xl font-bold text-white">{summary.total_threats}</p>
                </div>
                <ShieldExclamationIcon className="h-8 w-8 text-red-400" />
              </div>
            </div>

            <div className="bg-white/10 backdrop-blur-sm rounded-lg p-6 border border-white/20">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-300">Avg Confidence</p>
                  <p className="text-2xl font-bold text-white">{(summary.avg_confidence * 100).toFixed(1)}%</p>
                </div>
                <ChartBarIcon className="h-8 w-8 text-blue-400" />
              </div>
            </div>

            <div className="bg-white/10 backdrop-blur-sm rounded-lg p-6 border border-white/20">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-300">Critical Threats</p>
                  <p className="text-2xl font-bold text-red-400">
                    {summary.threats_by_level.critical || 0}
                  </p>
                </div>
                <ExclamationTriangleIcon className="h-8 w-8 text-red-400" />
              </div>
            </div>

            <div className="bg-white/10 backdrop-blur-sm rounded-lg p-6 border border-white/20">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-300">ML Status</p>
                  <p className="text-sm font-semibold text-green-400 flex items-center gap-1">
                    <CheckCircleIcon className="h-4 w-4" />
                    Active
                  </p>
                </div>
                <CpuChipIcon className="h-8 w-8 text-green-400" />
              </div>
            </div>
          </div>
        )}

        {/* Threat Events Table */}
        <div className="bg-white/10 backdrop-blur-sm rounded-lg border border-white/20">
          <div className="px-6 py-4 border-b border-white/20">
            <h2 className="text-xl font-semibold text-white flex items-center gap-2">
              <EyeIcon className="h-5 w-5" />
              Recent Threat Events
            </h2>
          </div>
          
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-white/5">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                    Threat
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                    Level
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                    Source
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                    Confidence
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                    Time
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/10">
                {threats.map((threat) => (
                  <tr key={threat.event_id} className="hover:bg-white/5 transition-colors">
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-3">
                        <span className={`p-2 rounded-lg ${getLevelColor(threat.level)}`}>
                          {getCategoryIcon(threat.category)}
                        </span>
                        <div>
                          <p className="text-sm font-medium text-white">{threat.description}</p>
                          <p className="text-xs text-gray-400">Category: {threat.category}</p>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border ${getLevelColor(threat.level)}`}>
                        {threat.level.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <div className="text-sm text-white">{threat.source_ip}</div>
                      <div className="text-xs text-gray-400">{threat.target}</div>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex items-center">
                        <div className="flex-1 bg-gray-700 rounded-full h-2 mr-3">
                          <div 
                            className="bg-blue-400 h-2 rounded-full" 
                            style={{ width: `${threat.confidence * 100}%` }}
                          ></div>
                        </div>
                        <span className="text-sm text-white">{(threat.confidence * 100).toFixed(0)}%</span>
                      </div>
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-300">
                      <div className="flex items-center gap-1">
                        <ClockIcon className="h-4 w-4" />
                        {new Date(threat.timestamp).toLocaleTimeString()}
                      </div>
                      <div className="text-xs text-gray-400">
                        {new Date(threat.timestamp).toLocaleDateString()}
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <button
                        onClick={() => setSelectedThreat(threat)}
                        className="text-blue-400 hover:text-blue-300 text-sm font-medium"
                      >
                        View Details
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {threats.length === 0 && (
            <div className="text-center py-12">
              <ShieldExclamationIcon className="mx-auto h-12 w-12 text-gray-400" />
              <h3 className="mt-2 text-sm font-medium text-gray-300">No threat events</h3>
              <p className="mt-1 text-sm text-gray-400">Try simulating some threats to see the detection in action.</p>
            </div>
          )}
        </div>

        {/* Threat Details Modal */}
        {selectedThreat && (
          <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50">
            <div className="bg-white/10 backdrop-blur-sm rounded-lg border border-white/20 p-6 max-w-2xl w-full mx-4 max-h-[80vh] overflow-y-auto">
              <div className="flex items-start justify-between mb-4">
                <h3 className="text-lg font-semibold text-white">Threat Event Details</h3>
                <button
                  onClick={() => setSelectedThreat(null)}
                  className="text-gray-400 hover:text-white"
                >
                  ×
                </button>
              </div>
              
              <div className="space-y-4">
                <div>
                  <label className="text-sm font-medium text-gray-300">Description</label>
                  <p className="text-white">{selectedThreat.description}</p>
                </div>
                
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="text-sm font-medium text-gray-300">Source IP</label>
                    <p className="text-white">{selectedThreat.source_ip}</p>
                  </div>
                  <div>
                    <label className="text-sm font-medium text-gray-300">Target</label>
                    <p className="text-white">{selectedThreat.target}</p>
                  </div>
                </div>
                
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="text-sm font-medium text-gray-300">Category</label>
                    <p className="text-white">{selectedThreat.category}</p>
                  </div>
                  <div>
                    <label className="text-sm font-medium text-gray-300">Confidence</label>
                    <p className="text-white">{(selectedThreat.confidence * 100).toFixed(1)}%</p>
                  </div>
                </div>
                
                <div>
                  <label className="text-sm font-medium text-gray-300">Mitigation Steps</label>
                  <ul className="list-disc list-inside text-white space-y-1">
                    {selectedThreat.mitigation.map((step, index) => (
                      <li key={index}>{step}</li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}